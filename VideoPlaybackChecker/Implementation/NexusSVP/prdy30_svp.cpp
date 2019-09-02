/******************************************************************************
 *  Broadcom Proprietary and Confidential. (c)2016 Broadcom. All rights reserved.
 *
 *  This program is the proprietary software of Broadcom and/or its licensors,
 *  and may only be used, duplicated, modified or distributed pursuant to the terms and
 *  conditions of a separate, written license agreement executed between you and Broadcom
 *  (an "Authorized License").  Except as set forth in an Authorized License, Broadcom grants
 *  no license (express or implied), right to use, or waiver of any kind with respect to the
 *  Software, and Broadcom expressly reserves all rights in and to the Software and all
 *  intellectual property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU
 *  HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY
 *  NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
 *
 *  Except as expressly set forth in the Authorized License,
 *
 *  1.     This program, including its structure, sequence and organization, constitutes the valuable trade
 *  secrets of Broadcom, and you shall use all reasonable efforts to protect the confidentiality thereof,
 *  and to use this information only in connection with your use of Broadcom integrated circuit products.
 *
 *  2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 *  AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
 *  WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 *  THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND ALL IMPLIED WARRANTIES
 *  OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,
 *  LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION
 *  OR CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF
 *  USE OR PERFORMANCE OF THE SOFTWARE.
 *
 *  3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR ITS
 *  LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL, INDIRECT, OR
 *  EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY RELATING TO YOUR
 *  USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF
 *  THE POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT
 *  ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE
 *  LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF
 *  ANY LIMITED REMEDY.
 ******************************************************************************/

#include "prdy30_svp.h"

#define LOG_NDEBUG 0
#include "nexus_config.h"

#include "nexus_platform.h"
#include "nexus_video_decoder.h"
#include "nexus_stc_channel.h"
#include "nexus_display.h"
#include "nexus_video_window.h"
#include "nexus_video_input.h"
#include "nexus_spdif_output.h"
#include "nexus_component_output.h"
#include "nexus_video_adj.h"
#include "nexus_playback.h"
#include "nexus_core_utils.h"

#include "common_crypto.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include "bstd.h"
#include "bkni.h"
#include "bkni_multi.h"
#include "bmp4_util.h"
#include "bbase64.h"
#include "piff_parser.h"
#include "bfile_stdio.h"
#include "bpiff.h"

#ifndef USE_OCDM
#include "drm_data.h"
#include "drmnamespace.h"
#include "drmbytemanip.h"
#include "drmmanager.h"
#include "drmbase64.h"
#include "drmmanagertypes.h"
#include "drmsoapxmlutility.h"
#include "oemcommon.h"
#include "drmconstants.h"
#include "drmsecuretime.h"
#include "drmsecuretimeconstants.h"

#else
#include "ocdm/open_cdm.h"

#define DRM_RESULT uint32_t

#define DRM_SUCCESS 0
#define DRM_E_CRYPTO_FAILED 1
#define DRM_E_FAIL 2
#define ChkDR(x) { \
    if (x) \
        goto ErrorExit; \
 }

struct Rpc_Secbuf_Info {
    uint32_t type;
    size_t size;
    void* token;
    void* token_enc;
    uint32_t subSamplesCount;
    uint32_t subSamples[];
};

#endif


#include "prdy_http.h"

#include "nxclient.h"
#include "nexus_surface_client.h"

#if SAGE_ENABLE
#include <sage_srai.h>
#endif

#include <time.h>
#include <sys/time.h>
#include <stdlib.h>

#define OZGUR

#ifdef OZGUR
#include "b_secbuf.h"
#endif

#define REPACK_VIDEO_PES_ID 0xE0
#define REPACK_AUDIO_PES_ID 0xC0

#define BOX_HEADER_SIZE (8)
#define BUF_SIZE (1024 * 1024 * 2) /* 2MB */

#define CALCULATE_PTS(t)        (((uint64_t)(t) / 10000LL) * 45LL)

// ~100 KB to start * 64 (2^6) ~= 6.4 MB, don't allocate more than ~6.4 MB
#define DRM_MAXIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE ( 64 * MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE )

BDBG_MODULE(prdy30_svp);


typedef struct app_ctx {
    FILE *fp_piff;
    uint32_t piff_filesize;

    uint8_t *pPayload;
    uint8_t *pOutBuf;

    size_t outBufSize;

    uint64_t last_video_fragment_time;
    uint64_t last_audio_fragment_time;
#ifndef USE_OCDM
    DRM_DECRYPT_CONTEXT decryptor;
#else
    struct OpenCDMSession *decryptor;
#endif
} app_ctx;

#ifdef USE_OCDM
typedef struct PRDY_APP_CONTEXT
{
    struct OpenCDMSystem       *pDrmAppCtx;          /* drm application context */
    struct OpenCDMSession      *pOEMContext;         /* Oem Context */
} PRDY_APP_CONTEXT;
#else
typedef struct PRDY_APP_CONTEXT
{
    DRM_APP_CONTEXT     *pDrmAppCtx;          /* drm application context */
    DRM_VOID            *pOEMContext;         /* Oem Context */
    DRM_BYTE            *pbOpaqueBuffer;      /* Opaque buffer */
    DRM_DWORD            cbOpaqueBuffer;
} PRDY_APP_CONTEXT;
#endif
typedef struct pthread_info {
    NEXUS_SimpleVideoDecoderHandle videoDecoder;
    int result;
} pthread_info;

/* stream type */
int vc1_stream = 0;
typedef app_ctx * app_ctx_t;
static int video_decode_hdr;

static NEXUS_Error gui_init( NEXUS_SurfaceClientHandle surfaceClient );
#ifdef ANDROID
static bool setupRuntimeHeaps( bool secureDecoder, bool secureHeap );
#endif

static int piff_playback_dma_buffer(CommonCryptoHandle commonCryptoHandle, void *dst,
        void *src, size_t size, bool flush)
{
    NEXUS_DmaJobBlockSettings blkSettings;
    CommonCryptoJobSettings cryptoJobSettings;

    BDBG_MSG(("%s: from=%p, to=%p, size=%u", __FUNCTION__, src, dst, (uint32_t)size));

    NEXUS_DmaJob_GetDefaultBlockSettings(&blkSettings);
    blkSettings.pSrcAddr = src;
    blkSettings.pDestAddr = dst;
    blkSettings.blockSize = size;
    blkSettings.resetCrypto = true;
    blkSettings.scatterGatherCryptoStart = true;
    blkSettings.scatterGatherCryptoEnd = true;

    if (flush)
    {
        /* Need to flush manually the source buffer (non secure heap). We need to flush manually as soon as we copy data into
           the secure heap. Setting blkSettings[ii].cached = true would also try to flush the destination address in the secure heap
           which is not accessible. This would cause the whole memory to be flushed at once. */
        NEXUS_FlushCache(blkSettings.pSrcAddr, blkSettings.blockSize);
        blkSettings.cached = false; /* Prevent the DMA from flushing the buffers later on */
    }

    CommonCrypto_GetDefaultJobSettings(&cryptoJobSettings);
    CommonCrypto_DmaXfer(commonCryptoHandle,  &cryptoJobSettings, &blkSettings, 1);

    if (flush)
    {
        /* Need to flush manually the source buffer (non secure heap). We need to flush manually as soon as we copy data into
           the secure heap. Setting blkSettings[ii].cached = true would also try to flush the destination address in the secure heap
           which is not accessible. This would cause the whole memory to be flushed at once. */
        NEXUS_FlushCache(blkSettings.pSrcAddr, blkSettings.blockSize);
    }

    return 0;
}

static int parse_esds_config(bmedia_adts_hdr *hdr, bmedia_info_aac *info_aac, size_t payload_size)
{
    bmedia_adts_header adts_header;

    bmedia_adts_header_init_aac(&adts_header, info_aac);
    bmedia_adts_hdr_init(hdr, &adts_header, payload_size);

    return 0;
}

static int parse_avcc_config(uint8_t *avcc_hdr, size_t *hdr_len, size_t *nalu_len,
        uint8_t *cfg_data, size_t cfg_data_size)
{
    bmedia_h264_meta meta;
    unsigned int i, sps_len, pps_len;
    uint8_t *data;
    uint8_t *dst;

    bmedia_read_h264_meta(&meta, cfg_data, cfg_data_size);

    *nalu_len = meta.nalu_len;

    data = (uint8_t *)meta.sps.data;
    dst = avcc_hdr;
    *hdr_len = 0;

    for(i = 0; i < meta.sps.no; i++)
    {
        sps_len = (((uint16_t)data[0]) <<8) | data[1];
        data += 2;
        /* Add NAL */
        BKNI_Memcpy(dst, bpiff_nal, sizeof(bpiff_nal)); dst += sizeof(bpiff_nal);
        /* Add SPS */
        BKNI_Memcpy(dst, data, sps_len);
        dst += sps_len;
        data += sps_len;
        *hdr_len += (sizeof(bpiff_nal) + sps_len);
    }

    data = (uint8_t *)meta.pps.data;
    for (i = 0; i < meta.pps.no; i++)
    {
        pps_len = (((uint16_t)data[0]) <<8) | data[1];
        data += 2;
        /* Add NAL */
        BKNI_Memcpy(dst, bpiff_nal, sizeof(bpiff_nal));
        dst += sizeof(bpiff_nal);
        /* Add PPS */
        BKNI_Memcpy(dst, data, pps_len);
        dst += pps_len;
        data += pps_len;
        *hdr_len += (sizeof(bpiff_nal) + pps_len);
    }
    return 0;
}

#if SAGE_ENABLE
static void *check_buffer(void *threadInfo )
{
    int i;
    pthread_info * info = (pthread_info *) threadInfo;

    if(info == NULL) {
        return NULL;
    }

    for (i = 0; i < 2; i++)
    {
        NEXUS_VideoDecoderStatus status;
        NEXUS_SimpleVideoDecoder_GetStatus(info->videoDecoder, &status);
        BDBG_MSG(("Main - numDecoded = '%u',   numDecodeErrors = '%u',   ptsErrorCount = '%u'", status.numDecoded, status.numDecodeErrors, status.ptsErrorCount));
        if (status.numDecodeErrors)
        {
            BDBG_ERR(("failing with numDecodeErrors = '%u'", status.numDecodeErrors));
            info->result = -1;
            break;
        }
        BKNI_Sleep(1000);
    }
    info->result = 0;

    return (void*)info;
}

void printBufferHex(const char name[], const uint8_t *buffer, size_t buffer_len)
{
    size_t wtf = buffer_len * 2;
    char *data = new char[wtf];
    for(size_t i=0; i < buffer_len; ++i)
    {
        sprintf(data+i*2, "%.2X ", buffer[i]);
    }
    fprintf(stderr, "***AG-PRINT*[%s:%d %s()]%s(%zu)=%s\n", __FILE__, __LINE__, __FUNCTION__, name, buffer_len, data);
    delete[] data;
}

static DRM_RESULT secure_process_fragment(CommonCryptoHandle commonCryptoHandle, app_ctx *app,
        piff_parse_frag_info *frag_info, size_t payload_size,
        void *decoder_data, size_t decoder_len,
        NEXUS_PlaypumpHandle playpump, BKNI_EventHandle event)
{
    uint32_t i, j, bytes_processed;
    bpiff_drm_mp4_box_se_sample *pSample;
    uint8_t pes_header[BMEDIA_PES_HEADER_MAX_SIZE];
    size_t pes_header_len;
    bmedia_pes_info pes_info;
    uint64_t frag_duration;
    uint8_t *pOutBuf = app->pOutBuf;
    size_t decrypt_offset = 0;
    NEXUS_PlaypumpStatus playpumpStatus;
    size_t fragment_size = payload_size;
    void *playpumpBuffer;
    size_t bufferSize;
    size_t outSize = 0;
    uint8_t *out;
    uint8_t *out2;
    size_t sampleSize = 0;
    DRM_RESULT dr = DRM_SUCCESS;

    /* Obtain secure playpump buffer */
    NEXUS_Playpump_GetStatus(playpump, &playpumpStatus);
    fragment_size += 512;   /* Provide headroom for PES and SPS/PPS headers */
    BDBG_ASSERT(fragment_size <= playpumpStatus.fifoSize);
    for(;;) {
        NEXUS_Playpump_GetBuffer(playpump, &playpumpBuffer, &bufferSize);
        if(bufferSize >= fragment_size) {
            break;
        }
        if(bufferSize==0) {
            BKNI_WaitForEvent(event, 100);
            continue;
        }
        if((uint8_t *)playpumpBuffer >= (uint8_t *)playpumpStatus.bufferBase +
                (playpumpStatus.fifoSize - fragment_size)) {
            NEXUS_Playpump_WriteComplete(playpump, bufferSize, 0); /* skip buffer what wouldn't be big enough */
        }
    }

    BDBG_MSG(("%s: NEXUS_Playpump_GetBuffer return buffer %p, size %u",
              __FUNCTION__, playpumpBuffer, (uint32_t)bufferSize));

    bytes_processed = 0;
    if (frag_info->samples_enc->sample_count != 0) {
        /* Iterate through the samples within the fragment */
        for (i = 0; i < frag_info->samples_enc->sample_count; i++) {
            size_t numOfByteDecrypted = 0;

            pSample = &frag_info->samples_enc->samples[i];
            sampleSize = frag_info->sample_info[i].size;

            pOutBuf = app->pOutBuf;
            app->outBufSize = 0;
            if (frag_info->trackType == BMP4_SAMPLE_ENCRYPTED_VIDEO) {
                if (!vc1_stream) {
                    /* H.264 Decoder configuration parsing */
                    uint8_t avcc_hdr[BPIFF_MAX_PPS_SPS];
                    size_t avcc_hdr_size;
                    size_t nalu_len = 0;

                    parse_avcc_config(avcc_hdr, &avcc_hdr_size, &nalu_len,  (uint8_t *)decoder_data, decoder_len);

                    bmedia_pes_info_init(&pes_info, REPACK_VIDEO_PES_ID);
                    frag_duration = app->last_video_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_video_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);
                    if (video_decode_hdr == 0) {
                        pes_header_len = bmedia_pes_header_init(pes_header,
                                (sampleSize + avcc_hdr_size - nalu_len + sizeof(bpiff_nal)), &pes_info);
                    } else {
                        pes_header_len = bmedia_pes_header_init(pes_header,
                                (sampleSize - nalu_len + sizeof(bpiff_nal)), &pes_info);
                    }

                    /* Copy PES header and SPS/PPS to intermediate buffer */
                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    pOutBuf += pes_header_len;
                    app->outBufSize += pes_header_len;

                    /* Only add header once */
                    if (video_decode_hdr == 0) {
                        BKNI_Memcpy(pOutBuf, avcc_hdr, avcc_hdr_size);
                        pOutBuf += avcc_hdr_size;
                        app->outBufSize += avcc_hdr_size;
                        video_decode_hdr = 1;
                    }
                    //printf("pes_header_len:%d avcc_hdr_size:%d decrypt_offset:%d PTS:%u\n",pes_header_len,avcc_hdr_size,decrypt_offset,pes_info.pts);
                    decrypt_offset = nalu_len;
                } else {
                    bmedia_pes_info_init(&pes_info, REPACK_VIDEO_PES_ID);
                    frag_duration = app->last_video_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_video_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);

                    pes_header_len = bmedia_pes_header_init(pes_header, sampleSize, &pes_info);
                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    pOutBuf += pes_header_len;
                    app->outBufSize += pes_header_len;
                }
            } else if (frag_info->trackType == BMP4_SAMPLE_ENCRYPTED_AUDIO) {
                if (!vc1_stream) {
                    /* AAC information parsing */
                    bmedia_adts_hdr hdr;
                    bmedia_info_aac *info_aac = (bmedia_info_aac *)decoder_data;

                    parse_esds_config(&hdr, info_aac, sampleSize);

                    bmedia_pes_info_init(&pes_info, REPACK_AUDIO_PES_ID);
                    frag_duration = app->last_audio_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_audio_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);

                    pes_header_len = bmedia_pes_header_init(pes_header,
                            (sampleSize + BMEDIA_ADTS_HEADER_SIZE), &pes_info);
                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    BKNI_Memcpy(pOutBuf + pes_header_len, &hdr.adts, BMEDIA_ADTS_HEADER_SIZE);

                    pOutBuf += pes_header_len + BMEDIA_ADTS_HEADER_SIZE;
                    app->outBufSize += pes_header_len + BMEDIA_ADTS_HEADER_SIZE;

                    decrypt_offset = 0;
                } else {
                    bmedia_pes_info_init(&pes_info, REPACK_AUDIO_PES_ID);
                    frag_duration = app->last_audio_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_audio_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);

                    pes_header_len = bmedia_pes_header_init(pes_header,
                            (bmedia_frame_bcma.len + sizeof(uint32_t) + decoder_len + sampleSize), &pes_info);
                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    pOutBuf += pes_header_len;
                    BKNI_Memcpy(pOutBuf, bmedia_frame_bcma.base, bmedia_frame_bcma.len);
                    pOutBuf += bmedia_frame_bcma.len;
                    B_MEDIA_SAVE_UINT32_BE(pOutBuf, sampleSize);
                    pOutBuf += sizeof(uint32_t);
                    BKNI_Memcpy(pOutBuf, decoder_data, decoder_len);
                    pOutBuf += decoder_len;
                    app->outBufSize += pes_header_len + bmedia_frame_bcma.len + sizeof(uint32_t) + decoder_len;
                }
            } else {
                BDBG_WRN(("%s Unsupported track type %d detected", __FUNCTION__, frag_info->trackType));
                return -1;
            }

            // move the buffer (
            piff_playback_dma_buffer(commonCryptoHandle, (uint8_t *)playpumpBuffer + outSize,
                    app->pOutBuf, app->outBufSize, true);
            outSize += app->outBufSize;

#ifdef OZGUR
#ifdef USE_OCDM
            fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_Alloc(size=%zu, type=B_Secbuf_Type_eGeneric, buffer=%p)\n", __FILE__, __LINE__, __FUNCTION__, sampleSize, &out);
            B_Error secBufAllocError = B_Secbuf_Alloc(sampleSize, B_Secbuf_Type_eGeneric, &out);
            if(secBufAllocError){
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_Alloc(size=%zu, type=B_Secbuf_Type_eGeneric, buffer=%p) FAILED (%d)\n", __FILE__, __LINE__, __FUNCTION__, sampleSize, &out, secBufAllocError);
            }
#else // USE_OCDM
            fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_Alloc(size=%zu, type=B_Secbuf_Type_eSecure, buffer=%p)\n", __FILE__, __LINE__, __FUNCTION__, sampleSize, &out);
            B_Secbuf_Alloc(sampleSize, B_Secbuf_Type_eSecure, &out);
#endif // USE_OCDM

            uint8_t *bufferData = (uint8_t *)playpumpBuffer + outSize;
            uint32_t bufferDataSize = 0;
#else
            out = (uint8_t *)playpumpBuffer + outSize;
#endif // OZGUR

#ifdef USE_OCDM
            // if there is no subsample, only allocate one region for clear+enc, otherwise, number of subsamples
            uint32_t subSamplesCount;
            if(pSample->nbOfEntries)
            {
                subSamplesCount = pSample->nbOfEntries * 2;
            }else {
                subSamplesCount = 2;
            }

            uint32_t sizeOfRPCInfo = sizeof(struct Rpc_Secbuf_Info) + ( subSamplesCount * sizeof(uint32_t) );
            struct Rpc_Secbuf_Info *RPCsecureBufferInfo = (struct Rpc_Secbuf_Info*)(malloc(sizeOfRPCInfo));
            RPCsecureBufferInfo->subSamplesCount = subSamplesCount;
#endif // USE_OCDM

            if(frag_info->samples_enc->flags & 0x000002) {
                uint64_t     qwOffset = 0;

                uint32_t *pEncryptedRegionMappings = NULL;
#ifdef WTF_CODE
                NEXUS_DmaJobBlockSettings *blkSettings = NULL;
                CommonCryptoJobSettings cryptoJobSettings;
#endif // WTF_CODE
                size_t entryNb = 0;
                int blk_idx = 0;
                int k = 0;
//#ifdef !USE_OCDM
                pEncryptedRegionMappings = (uint32_t *)BKNI_Malloc( sizeof(uint32_t) * pSample->nbOfEntries * 2);
                if(pEncryptedRegionMappings == NULL){
                    return -1;
                }
// #endif // !USE_OCDM
#ifdef WTF_CODE
                blkSettings = (NEXUS_DmaJobBlockSettings *)BKNI_Malloc( sizeof(NEXUS_DmaJobBlockSettings) * pSample->nbOfEntries * 2);
                if(blkSettings == NULL){
                    BKNI_Free(pEncryptedRegionMappings);
                    return -1;
                }
#endif // WTF_CODE
                uint32_t num_clear;
                uint32_t num_enc;
                for(j = 0; j < pSample->nbOfEntries; j++) {

                    num_clear = pSample->entries[j].bytesOfClearData;
                    num_enc = pSample->entries[j].bytesOfEncData;
//#ifdef !USE_OCDM
                    pEncryptedRegionMappings[entryNb++] = num_clear;
                    pEncryptedRegionMappings[entryNb++] = num_enc;
//#endif !USE_OCDM
#ifdef USE_OCDM
                    RPCsecureBufferInfo->subSamples[j] = num_clear;
                    RPCsecureBufferInfo->subSamples[j+1] = num_enc;
#endif
                    /* Skip over clear units by offset amount */
                    BDBG_ASSERT(num_clear >= decrypt_offset);
                    batom_cursor_skip((batom_cursor *)&frag_info->cursor, decrypt_offset);

                    if (!vc1_stream) {
                        B_Secbuf_ImportData(out, bufferDataSize, (uint8_t*)bpiff_nal, sizeof(bpiff_nal), 0);
                        bufferDataSize += sizeof(bpiff_nal);
                    }

                    B_Secbuf_ImportData(out, bufferDataSize, (uint8_t *)frag_info->cursor.cursor, (num_enc + num_clear - decrypt_offset), true);
                    bufferDataSize += (num_enc + num_clear - decrypt_offset);

                    /* Skip over remaining clear units */
                    batom_cursor_skip((batom_cursor *)&frag_info->cursor, (num_clear - decrypt_offset));

                    batom_cursor_skip((batom_cursor *)&frag_info->cursor,num_enc);
                    qwOffset = num_enc;
                    numOfByteDecrypted  += (num_clear - decrypt_offset + num_enc);

                    if(numOfByteDecrypted > sampleSize) {
                        BDBG_WRN(("Wrong buffer size is detected while decrypting the ciphertext, bytes processed %d, sample size to decrypt %d",
                                  (uint32_t)numOfByteDecrypted, (uint32_t)sampleSize));
#ifdef WTF_CODE
                        BKNI_Free(blkSettings);
#endif // WTF_CODE
                        BKNI_Free(pEncryptedRegionMappings);
                        return -1;
                    }
                }
#ifdef WTF_CODE
                B_Secbuf_ImportData(out, 0, NULL, 0, 1);
#endif // WTF_CODE
                uint8_t* tokenBuffer = out;
                B_Secbuf_Info   BsecureBufferInfo;
                B_Secbuf_GetBufferInfo(out, &BsecureBufferInfo);

#ifdef USE_OCDM
                RPCsecureBufferInfo->type = BsecureBufferInfo.type;
                RPCsecureBufferInfo->size = BsecureBufferInfo.size;
                RPCsecureBufferInfo->token = NULL;
                RPCsecureBufferInfo->token_enc = BsecureBufferInfo.token;

                const uint32_t reversedIVCount = 8;
                uint8_t * reversedIV = static_cast<uint8_t *>(&pSample->iv[8]);
                for (uint32_t i = 0; i < reversedIVCount / 2; i++) {
                    uint8_t temp = reversedIV[i];
                    reversedIV[i] = reversedIV[reversedIVCount - i - 1];
                    reversedIV[reversedIVCount - i - 1] = temp;
                }
#if AG_DEBUG_PRINTFS
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamplesCount=%zu\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamplesCount);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamples[0]=%d\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamples[0]);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamples[1]=%d\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamples[1]);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 tokenBufferSize=%d\n", __FILE__, __LINE__, __FUNCTION__, sizeOfRPCInfo);
                printBufferHex("OCDM2 qwInitializationVector", (uint8_t*)&pSample->iv[8], 8);
#endif
                OpenCDMError decryptStatus = opencdm_session_decrypt(
                    app->decryptor,
                    (uint8_t*)(RPCsecureBufferInfo),
                    sizeOfRPCInfo,
                    &pSample->iv[8], 8,
                    nullptr, 0,
                    0);

                if (decryptStatus != 0) {
                    // Oopsie daisy... Failure
                    printf("1 Decryption is failed!!! %s%d\n",__FUNCTION__,__LINE__);
                }

                void *opaqueData; // TODO: may require freeing
                size_t allocSize=sampleSize;
                B_Error allocWithTokenError = B_Secbuf_AllocWithToken(allocSize, B_Secbuf_Type_eSecure, RPCsecureBufferInfo->token, &opaqueData);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_AllocWithToken(size=%zu, type=B_Secbuf_Type_eSecure, token=%p, buffer=%p)\n", __FILE__, __LINE__, __FUNCTION__, allocSize, RPCsecureBufferInfo->token, opaqueData);;
                if(allocWithTokenError){
                    fprintf(stderr, "***AG-PRINT*[%s:%d %s] B_Secbuf_AllocWithToken failed(%d)\n", __FILE__, __LINE__, __FUNCTION__, allocWithTokenError);
                    exit(1029482);
                }
#else // USE_OCDM
                DRM_AES_COUNTER_MODE_CONTEXT aesCtrInfo = { 0, 0, 0 };

                /* Process and decrypt samples */
                BKNI_Memcpy( &aesCtrInfo.qwInitializationVector,&pSample->iv[8],8);

                DRM_DWORD tokenBufferSize = BsecureBufferInfo.size;
#if AG_DEBUG_PRINTFS
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT1 subsamplesCount=%zu\n", __FILE__, __LINE__, __FUNCTION__, pSample->nbOfEntries *2);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT1 subsamples[0]=%d\n", __FILE__, __LINE__, __FUNCTION__, pEncryptedRegionMappings[0]);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT1 subsamples[1]=%d\n", __FILE__, __LINE__, __FUNCTION__, pEncryptedRegionMappings[1]);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT1 tokenBufferSize=%d\n", __FILE__, __LINE__, __FUNCTION__, BsecureBufferInfo.size);
            printBufferHex("DIRECT1 qwInitializationVector", (uint8_t*)&aesCtrInfo.qwInitializationVector, 8);
#endif
                dr = Drm_Reader_DecryptOpaque (
                                &app->decryptor,
                                pSample->nbOfEntries *2,
                                pEncryptedRegionMappings,
                                aesCtrInfo.qwInitializationVector,
                                tokenBufferSize,
                                tokenBuffer,
                                &tokenBufferSize,
                                &tokenBuffer );
#endif // USE_OCDM
                B_Secbuf_ExportData(out, 0, bufferData, bufferDataSize, true);

#ifdef WTF_CODE
                BKNI_Free(blkSettings);
#endif // WTF_CODE
                BKNI_Free(pEncryptedRegionMappings);
                ChkDR(dr);

            } else {
                uint32_t encryptedRegionMappings[2];
                B_Secbuf_ImportData(out, bufferDataSize, (uint8_t *)frag_info->cursor.cursor, sampleSize, 1);

                bufferDataSize = sampleSize;
                encryptedRegionMappings[0] = 0; /* 0 bytes of clear */
                encryptedRegionMappings[1] = sampleSize; /* all bytes are encrypted*/

                BDBG_MSG(("%s:%d: Drm_Reader_DecryptOpaque(..., ..., %p, %u)",
                          __FUNCTION__, __LINE__, out, (uint32_t)sampleSize));

                uint8_t* tokenBuffer = out;
                B_Secbuf_Info   BsecureBufferInfo;
                B_Secbuf_GetBufferInfo(out, &BsecureBufferInfo);
                uint32_t tokenBufferSize = BsecureBufferInfo.size;

#ifdef USE_OCDM
#if AG_DEBUG_PRINTFS
                printf("*** token_enc 2 %s\n",__FUNCTION__);
#endif
                RPCsecureBufferInfo->type = BsecureBufferInfo.type;
                RPCsecureBufferInfo->size = BsecureBufferInfo.size;
                RPCsecureBufferInfo->token = NULL;
                RPCsecureBufferInfo->token_enc = BsecureBufferInfo.token;
                RPCsecureBufferInfo->subSamples[0] = 0;
                RPCsecureBufferInfo->subSamples[1] = sampleSize;

                // reverse the pSample->iv[] vector
                uint32_t reversedIVCount = 8;
                uint8_t * reversedIV = static_cast<uint8_t *>(&pSample->iv[8]);
                for (uint32_t i = 0; i < reversedIVCount / 2; i++) {
                    uint8_t temp = reversedIV[i];
                    reversedIV[i] = reversedIV[reversedIVCount - i - 1];
                    reversedIV[reversedIVCount - i - 1] = temp;
                }

#if AG_DEBUG_PRINTFS
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamplesCount=%zu\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamplesCount);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamples[0]=%d\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamples[0]);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 subsamples[1]=%d\n", __FILE__, __LINE__, __FUNCTION__, RPCsecureBufferInfo->subSamples[1]);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s]OCDM2 tokenBufferSize=%d\n", __FILE__, __LINE__, __FUNCTION__, sizeOfRPCInfo);
                printBufferHex("OCDM2 qwInitializationVector", (uint8_t*)&pSample->iv[8], 8);
#endif
                OpenCDMError decryptStatus = opencdm_session_decrypt(
                    app->decryptor,
                    (uint8_t*)(RPCsecureBufferInfo),
                    sizeOfRPCInfo,
                    &pSample->iv[8], 8,
                    nullptr, 0,
                    0);

                if (decryptStatus != 0) {
                    // Oopsie daisy... Failure
                    printf("Decryption is failed!!! %s%d\n",__FUNCTION__,__LINE__);
                }

                void *opaqueData;
                size_t allocSize=sampleSize;
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_AllocWithToken(size=%zu, type=B_Secbuf_Type_eSecure, token=%p, buffer=%p)\n", __FILE__, __LINE__, __FUNCTION__, allocSize, RPCsecureBufferInfo->token, opaqueData);;
                B_Error allocWithTokenError = B_Secbuf_AllocWithToken(allocSize, B_Secbuf_Type_eSecure, RPCsecureBufferInfo->token, &opaqueData);
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] B_Secbuf_AllocWithToken(size=%zu, type=B_Secbuf_Type_eSecure, token=%p, buffer=%p)\n", __FILE__, __LINE__, __FUNCTION__, allocSize, RPCsecureBufferInfo->token, opaqueData);;
                if(allocWithTokenError){
                    fprintf(stderr, "***AG-PRINT*[%s:%d %s] 2 allocWithTokenError=%d\n", __FILE__, __LINE__, __FUNCTION__, allocWithTokenError);
                    exit(1029482);
                }
                // B_Secbuf_FreeDesc(opaqueData);

#else // USE_OCDM
                DRM_AES_COUNTER_MODE_CONTEXT aesCtrInfo = { 0, 0, 0 };

                /* Process and decrypt samples */
                BKNI_Memcpy( &aesCtrInfo.qwInitializationVector,&pSample->iv[8],8);

#if AG_DEBUG_PRINTFS
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT2 subsamplesCount=%zu\n", __FILE__, __LINE__, __FUNCTION__, 2);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT2 subsamples[0]=%d\n", __FILE__, __LINE__, __FUNCTION__, encryptedRegionMappings[0]);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT2 subsamples[1]=%d\n", __FILE__, __LINE__, __FUNCTION__, encryptedRegionMappings[1]);
            fprintf(stderr, "***AG-PRINT*[%s:%d %s]DIRECT2 tokenBufferSize=%d\n", __FILE__, __LINE__, __FUNCTION__, BsecureBufferInfo.size);
            printBufferHex("DIRECT2 qwInitializationVector", (uint8_t*)&aesCtrInfo.qwInitializationVector, 8);
#endif
                ChkDR(Drm_Reader_DecryptOpaque(
                                &app->decryptor,
                                2,
                                encryptedRegionMappings,
                                aesCtrInfo.qwInitializationVector,
                                tokenBufferSize,
                                tokenBuffer,
                                &tokenBufferSize,
                                &tokenBuffer ));
#endif // USE_OCDM
                B_Secbuf_ExportData(out, 0, bufferData, bufferDataSize, true);

                batom_cursor_skip((batom_cursor *)&frag_info->cursor, sampleSize);
                numOfByteDecrypted = sampleSize;
            }

            outSize += bufferDataSize;

            bytes_processed += numOfByteDecrypted + decrypt_offset;
#ifdef USE_OCDM
            B_Secbuf_FreeDesc(out);
            if(RPCsecureBufferInfo) free(RPCsecureBufferInfo);
#endif // USE_OCDM

        }
        BDBG_MSG(("%s: NEXUS_Playpump_WriteComplete buffer %p, size %u",
                  __FUNCTION__, playpumpBuffer, (uint32_t)outSize));
        NEXUS_Error playpumpWCstatus = NEXUS_Playpump_WriteComplete(playpump, 0, outSize);
        fprintf(stderr, "%s: NEXUS_Playpump_WriteComplete buffer %p, size %u, status = %u\n", __FUNCTION__, playpumpBuffer, (uint32_t)outSize, playpumpWCstatus);
    }

    if(bytes_processed != payload_size) {
        BDBG_WRN(("%s the number of bytes %d decrypted doesn't match the actual size %d of the payload, return failure...%d",__FUNCTION__,
                  bytes_processed, (uint32_t)payload_size, __LINE__));
        dr = DRM_E_CRYPTO_FAILED;
    }

ErrorExit:
    return dr;
}

#else

static DRM_RESULT decrypt_sample(CommonCryptoHandle commonCryptoHandle,
        uint32_t sampleSize, batom_cursor * cursor,
        bpiff_drm_mp4_box_se_sample *pSample, uint32_t *bytes_processed,
        DRM_DECRYPT_CONTEXT *decryptor, uint32_t enc_flags,
        uint8_t *out, size_t decrypt_offset)
{
    DRM_RESULT dr = DRM_SUCCESS;
    uint8_t i=0;
    uint8_t *src;
    uint8_t *dst;
    uint8_t *out2;
    DRM_AES_COUNTER_MODE_CONTEXT     aesCtrInfo;

    *bytes_processed = 0;

    BKNI_Memcpy( &aesCtrInfo.qwInitializationVector,&pSample->iv[8],8);
    aesCtrInfo.qwBlockOffset = 0;
    aesCtrInfo.bByteOffset = 0;
    out2 = out;

    if(enc_flags & 0x000002) {
        size_t       entryNb = 0;
        uint32_t    *pEncryptedRegionMappings = (uint32_t *)BKNI_Malloc( sizeof(uint32_t) * pSample->nbOfEntries * 2);

        for(i = 0; i <  pSample->nbOfEntries; i++) {
            uint32_t num_clear = pSample->entries[i].bytesOfClearData;
            uint32_t num_enc = pSample->entries[i].bytesOfEncData;

            pEncryptedRegionMappings[entryNb++] = num_clear;
            pEncryptedRegionMappings[entryNb++] = num_enc;

            /* Skip over clear units by offset amount */
            BDBG_ASSERT(num_clear >= decrypt_offset);
            batom_cursor_skip((batom_cursor *)cursor, decrypt_offset);

            /* Add NAL header per entry */
            if (!vc1_stream) {
                BKNI_Memcpy(out, bpiff_nal, sizeof(bpiff_nal));
                out += sizeof(bpiff_nal);
            }

            src = (uint8_t *)cursor->cursor;
            dst = out;

            piff_playback_dma_buffer(commonCryptoHandle, dst, src,
                    (num_enc + num_clear - decrypt_offset), false);

            /* Skip over remaining clear units */
            out += (num_clear - decrypt_offset);
            batom_cursor_skip((batom_cursor *)cursor, (num_clear - decrypt_offset));

            out += num_enc;
            batom_cursor_skip((batom_cursor *)cursor,num_enc);
            if (!vc1_stream)
                *bytes_processed  += (num_clear - decrypt_offset +
                        num_enc + sizeof(bpiff_nal));
            else
                *bytes_processed  += (num_clear - decrypt_offset + num_enc);

            if( *bytes_processed > sampleSize) {
                BDBG_WRN(("Wrong buffer size is detected while decrypting the ciphertext, bytes processed %d, sample size to decrypt %d",*bytes_processed,sampleSize));
                ChkDR(DRM_E_FAIL);
            }

        }

            BDBG_MSG(("%s:%d: DRM_Prdy_Reader_Decrypt(..., ..., %p)",
                  __FUNCTION__, __LINE__, out));


            dr = Drm_Reader_DecryptOpaque(
                            decryptor,
                            pSample->nbOfEntries *2,
                            pEncryptedRegionMappings,
                            aesCtrInfo.qwInitializationVector,
                            sampleSize,
                            out2,
                            (DRM_DWORD*)&sampleSize,
                            &out2 );

            BKNI_Free(pEncryptedRegionMappings);

            if (dr != DRM_SUCCESS)
            {
                BDBG_ERR(("%s Drm_Reader_DecryptOpaque - %d dr = 0x%x", __FUNCTION__, __LINE__, (unsigned int)dr));
                goto ErrorExit;
            }

    }
    else
    {
        uint32_t encryptedRegionMappings[2];

        src = (uint8_t *)cursor->cursor;
        dst = out;

        piff_playback_dma_buffer(commonCryptoHandle, dst, src, sampleSize, false);

        BDBG_MSG(("%s:%d: Drm_Reader_DecryptOpaque(..., ..., %p, %u)",
                  __FUNCTION__, __LINE__, out, (uint32_t)sampleSize));

        encryptedRegionMappings[0] = 0; /* 0 bytes of clear */
        encryptedRegionMappings[1] = sampleSize; /* all bytes are encrypted*/

        dr = Drm_Reader_DecryptOpaque(
                decryptor,
                2,
                encryptedRegionMappings,
                aesCtrInfo.qwInitializationVector,
                sampleSize,
                out,
                (DRM_DWORD*)&sampleSize,
                &out );
        if (dr != DRM_SUCCESS)
        {
            BDBG_ERR(("%s Drm_Reader_DecryptOpaque failed - %d dr = 0x%x", __FUNCTION__, __LINE__, (unsigned int)dr));
            goto ErrorExit;
        }

        out += (sampleSize);

        batom_cursor_skip((batom_cursor *)cursor, sampleSize);
        *bytes_processed = sampleSize;
    }

ErrorExit:
    return dr;
}

static int process_fragment(CommonCryptoHandle commonCryptoHandle, app_ctx *app, piff_parse_frag_info *frag_info,
        size_t payload_size, void *decoder_data, size_t decoder_len)
{
    int rc = 0;
    uint32_t i, bytes_processed;
    bpiff_drm_mp4_box_se_sample *pSample;
    uint8_t pes_header[BMEDIA_PES_HEADER_MAX_SIZE];
    size_t pes_header_len;
    bmedia_pes_info pes_info;
    uint64_t frag_duration;
    uint8_t *pOutBuf = app->pOutBuf;
    size_t decrypt_offset = 0;

    app->outBufSize = 0;
    bytes_processed = 0;
    if (frag_info->samples_enc->sample_count != 0) {
        for (i = 0; i < frag_info->samples_enc->sample_count; i++) {
            size_t numOfByteDecrypted = 0;
            size_t sampleSize = 0;

            pSample = &frag_info->samples_enc->samples[i];
            sampleSize = frag_info->sample_info[i].size;

            if (frag_info->trackType == BMP4_SAMPLE_ENCRYPTED_VIDEO) {
                if (!vc1_stream) {
                    /* H.264 Decoder configuration parsing */
                    uint8_t avcc_hdr[BPIFF_MAX_PPS_SPS];
                    size_t avcc_hdr_size;
                    size_t nalu_len = 0;

                    parse_avcc_config(avcc_hdr, &avcc_hdr_size, &nalu_len, (uint8_t *)decoder_data, decoder_len);

                    bmedia_pes_info_init(&pes_info, REPACK_VIDEO_PES_ID);
                    frag_duration = app->last_video_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_video_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);
                    if (video_decode_hdr == 0) {
                        pes_header_len = bmedia_pes_header_init(pes_header,
                                (sampleSize + avcc_hdr_size - nalu_len + sizeof(bpiff_nal)), &pes_info);
                    } else {
                        pes_header_len = bmedia_pes_header_init(pes_header,
                                (sampleSize - nalu_len + sizeof(bpiff_nal)), &pes_info);
                    }

                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    pOutBuf += pes_header_len;
                    app->outBufSize += pes_header_len;

                    if (video_decode_hdr == 0) {
                        BKNI_Memcpy(pOutBuf, avcc_hdr, avcc_hdr_size);
                        pOutBuf += avcc_hdr_size;
                        app->outBufSize += avcc_hdr_size;
                        video_decode_hdr = 1;
                    }

                    decrypt_offset = nalu_len;
                }
            } else if (frag_info->trackType == BMP4_SAMPLE_ENCRYPTED_AUDIO) {
                if (!vc1_stream) {
                    /* AAC information parsing */
                    bmedia_adts_hdr hdr;
                    bmedia_info_aac *info_aac = (bmedia_info_aac *)decoder_data;

                    parse_esds_config(&hdr, info_aac, sampleSize);

                    bmedia_pes_info_init(&pes_info, REPACK_AUDIO_PES_ID);
                    frag_duration = app->last_audio_fragment_time +
                        (int32_t)frag_info->sample_info[i].composition_time_offset;
                    app->last_audio_fragment_time += frag_info->sample_info[i].duration;

                    pes_info.pts_valid = true;
                    pes_info.pts = CALCULATE_PTS(frag_duration);

                    pes_header_len = bmedia_pes_header_init(pes_header,
                            (sampleSize + BMEDIA_ADTS_HEADER_SIZE), &pes_info);
                    BKNI_Memcpy(pOutBuf, &pes_header, pes_header_len);
                    BKNI_Memcpy(pOutBuf + pes_header_len, &hdr.adts, BMEDIA_ADTS_HEADER_SIZE);

                    pOutBuf += pes_header_len + BMEDIA_ADTS_HEADER_SIZE;
                    app->outBufSize += pes_header_len + BMEDIA_ADTS_HEADER_SIZE;

                    decrypt_offset = 0;
                }
            } else {
                BDBG_WRN(("%s Unsupported track type %d detected", __FUNCTION__, frag_info->trackType));
                return -1;
            }

            if(decrypt_sample(commonCryptoHandle, sampleSize, &frag_info->cursor, pSample, &numOfByteDecrypted,
                        &app->decryptor, frag_info->samples_enc->flags, pOutBuf, decrypt_offset) !=0) {
                BDBG_ERR(("%s Failed to decrypt sample, can't continue - %d", __FUNCTION__, __LINE__));
                return -1;
                break;
            }
            pOutBuf += numOfByteDecrypted;
            app->outBufSize += numOfByteDecrypted;
            bytes_processed += numOfByteDecrypted;
        }
    }

    if( bytes_processed != payload_size) {
        BDBG_WRN(("%s the number of bytes %d decrypted doesn't match the actual size %d of the payload, return failure...%d",__FUNCTION__,bytes_processed,payload_size, __LINE__));
        rc = -1;
    }

    return rc;
}

static int send_fragment_data(
        CommonCryptoHandle commonCryptoHandle,
        uint8_t *pData,
        uint32_t dataSize,
        NEXUS_PlaypumpHandle playpump,
        BKNI_EventHandle event)
{
    NEXUS_PlaypumpStatus playpumpStatus;
    size_t fragment_size = dataSize;
    void *playpumpBuffer;
    size_t bufferSize;
    NEXUS_Playpump_GetStatus(playpump, &playpumpStatus);
    fragment_size += 512;
    BDBG_ASSERT(fragment_size <= playpumpStatus.fifoSize);
    for(;;) {
        NEXUS_Playpump_GetBuffer(playpump, &playpumpBuffer, &bufferSize);
        if(bufferSize >= fragment_size) {
            break;
        }
        if(bufferSize==0) {
            BKNI_WaitForEvent(event, 100);
            continue;
        }
        if((uint8_t *)playpumpBuffer >= (uint8_t *)playpumpStatus.bufferBase +
                (playpumpStatus.fifoSize - fragment_size)) {
            NEXUS_Playpump_WriteComplete(playpump, bufferSize, 0); /* skip buffer what wouldn't be big enough */
        }
    }
    piff_playback_dma_buffer(commonCryptoHandle, playpumpBuffer, pData, dataSize, true);
    NEXUS_Playpump_WriteComplete(playpump, 0, dataSize);

    return 0;
}

#endif /* #if SAGE_ENABLE */


static void play_callback(void *context, int param)
{
    BSTD_UNUSED(param);
    BKNI_SetEvent((BKNI_EventHandle)context);
}

static void
wait_for_drain(NEXUS_PlaypumpHandle videoPlaypump, NEXUS_SimpleVideoDecoderHandle videoDecoder,
               NEXUS_PlaypumpHandle audioPlaypump, NEXUS_SimpleAudioDecoderHandle audioDecoder)
{
    NEXUS_Error rc;
    NEXUS_PlaypumpStatus playpumpStatus;

    for(;;) {
        rc=NEXUS_Playpump_GetStatus(videoPlaypump, &playpumpStatus);
        if(rc!=NEXUS_SUCCESS)
            break;

        if(playpumpStatus.fifoDepth==0) {
            break;
        }
        BKNI_Sleep(100);
    }
    for(;;) {
        rc=NEXUS_Playpump_GetStatus(audioPlaypump, &playpumpStatus);
        if(rc!=NEXUS_SUCCESS)
            break;

        if(playpumpStatus.fifoDepth==0)
            break;

        BKNI_Sleep(100);
    }

    if(videoDecoder) {
        for(;;) {
            NEXUS_VideoDecoderStatus decoderStatus;
            rc=NEXUS_SimpleVideoDecoder_GetStatus(videoDecoder, &decoderStatus);
            if(rc!=NEXUS_SUCCESS)
                break;

            if(decoderStatus.queueDepth==0)
                break;

            BKNI_Sleep(100);
        }
    }
    if(audioDecoder) {
        for(;;) {
            NEXUS_AudioDecoderStatus decoderStatus;
            rc=NEXUS_SimpleAudioDecoder_GetStatus(audioDecoder, &decoderStatus);
            if(rc!=NEXUS_SUCCESS)
                break;

            if(decoderStatus.queuedFrames < 4)
                break;

            BKNI_Sleep(100);
        }
    }
    return;
}

static int complete_play_fragments(
        NEXUS_SimpleAudioDecoderHandle audioDecoder,
        NEXUS_SimpleVideoDecoderHandle videoDecoder,
        NEXUS_PlaypumpHandle videoPlaypump,
        NEXUS_PlaypumpHandle audioPlaypump,
        NEXUS_DisplayHandle display,
        NEXUS_PidChannelHandle audioPidChannel,
        NEXUS_PidChannelHandle videoPidChannel,
        NEXUS_VideoWindowHandle window,
        BKNI_EventHandle event)
{
    BSTD_UNUSED(window);
    BSTD_UNUSED(display);
    BSTD_UNUSED(event);
    wait_for_drain(videoPlaypump, videoDecoder, audioPlaypump, audioDecoder);

    if (event != NULL) BKNI_DestroyEvent(event);

    if (videoDecoder) {
        NEXUS_SimpleVideoDecoder_Stop(videoDecoder);
        NEXUS_Playpump_ClosePidChannel(videoPlaypump, videoPidChannel);
        NEXUS_Playpump_Stop(videoPlaypump);
        NEXUS_StopCallbacks(videoPlaypump);
    }
    if (audioDecoder) {
        NEXUS_SimpleAudioDecoder_Stop(audioDecoder);
        NEXUS_Playpump_ClosePidChannel(audioPlaypump, audioPidChannel);
        NEXUS_Playpump_Stop(audioPlaypump);
        NEXUS_StopCallbacks(audioPlaypump);
    }

    NEXUS_Playpump_Close(videoPlaypump);
    NEXUS_Playpump_Close(audioPlaypump);

    return 0;
}
#ifndef USE_OCDM
DRM_API DRM_RESULT DRM_CALL DRMTOOLS_PrintOPLOutputIDs( __in const DRM_OPL_OUTPUT_IDS *f_pOPLs )
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_DWORD i;
    DRM_WCHAR rgwszGUID[DRM_GUID_STRING_LEN+1] = {0};
    DRM_CHAR  rgszGUID[DRM_NO_OF(rgwszGUID)] = {0};

    printf("    (%d GUIDs)\r\n", f_pOPLs->cIds );
    for( i = 0; i < f_pOPLs->cIds; i++ )
    {
        ChkDR( DRM_UTL_GuidToString( &f_pOPLs->rgIds[i], rgwszGUID ) );
        /* Safe to use, input parameter is in ASCII */
        DRM_UTL_DemoteUNICODEtoASCII( rgwszGUID, rgszGUID, DRM_NO_OF(rgwszGUID)-1 );

        printf("    GUID = %s\r\n", rgszGUID);
    }
    printf("\r\n");
ErrorExit:
    return dr;
}

DRM_API DRM_RESULT DRM_CALL DRMTOOLS_PrintVideoOutputProtectionIDs( __in const DRM_VIDEO_OUTPUT_PROTECTION_IDS_EX *f_pOPLs )
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_DWORD i;
    DRM_WCHAR rgwszGUID[DRM_GUID_STRING_LEN+1] = {0};
    DRM_CHAR  rgszGUID[DRM_NO_OF(rgwszGUID)] = {0};

    printf("    (%d entries)\r\n", f_pOPLs->cEntries );
    for( i = 0; i < f_pOPLs->cEntries; i++ )
    {
        ChkDR( DRM_UTL_GuidToString( &f_pOPLs->rgVop[i].guidId,
                            rgwszGUID ) );
        /* Safe to use, input parameter is in ASCII */
        DRM_UTL_DemoteUNICODEtoASCII( rgwszGUID, rgszGUID, DRM_NO_OF(rgwszGUID)-1 );

        printf("    GUID = %s\r\n", rgszGUID);
    }
    printf("\r\n");
ErrorExit:
    return dr;
}
#endif

/* This function, copied from Nexus, does not promise an exact match. Instead, it returns a NEXUS_VideoFormat which most closely matches the given info.
This allows us to make general configuration decisions.
Always make sure there's no 50/60 Hz or interlaced/progressive mixup. */
#define LOCAL_1080P_HEIGHT      (1080)
#define LOCAL_720P_HEIGHT       (720)
#define LOCAL_576P_HEIGHT       (576)

static NEXUS_VideoFormat getVideoFormatFromInfo(unsigned height, unsigned frameRate, bool interlaced)
{
    bool is50 = (frameRate == NEXUS_VideoFrameRate_e50) || (frameRate == NEXUS_VideoFrameRate_e25);

    if (height > LOCAL_1080P_HEIGHT) {
        switch (frameRate) {
        case NEXUS_VideoFrameRate_e23_976:
        case NEXUS_VideoFrameRate_e24:
            return NEXUS_VideoFormat_e3840x2160p24hz;
        case NEXUS_VideoFrameRate_e25: return NEXUS_VideoFormat_e3840x2160p25hz;
        case NEXUS_VideoFrameRate_e29_97: return NEXUS_VideoFormat_e3840x2160p30hz;
        case NEXUS_VideoFrameRate_e30: return NEXUS_VideoFormat_e3840x2160p30hz;
        case NEXUS_VideoFrameRate_e50: return NEXUS_VideoFormat_e3840x2160p50hz;
        default: return NEXUS_VideoFormat_e3840x2160p60hz; /* 60hz */
        }
    }

    if (height > LOCAL_720P_HEIGHT) {
        if (interlaced) {
            return is50 ? NEXUS_VideoFormat_e1080i50hz : NEXUS_VideoFormat_e1080i;
        }
        else {
            switch (frameRate) {
            case NEXUS_VideoFrameRate_e23_976:
            case NEXUS_VideoFrameRate_e24:
                return NEXUS_VideoFormat_e1080p24hz;
            case NEXUS_VideoFrameRate_e25: return NEXUS_VideoFormat_e1080p25hz;
            case NEXUS_VideoFrameRate_e29_97: return NEXUS_VideoFormat_e1080p30hz;
            case NEXUS_VideoFrameRate_e30: return NEXUS_VideoFormat_e1080p30hz;
            case NEXUS_VideoFrameRate_e50: return NEXUS_VideoFormat_e1080p50hz;
            default: return NEXUS_VideoFormat_e1080p; /* 60hz */
            }
        }
    }

    /* NOTE: the analog height of 480p is 483 */
    if (((is50 && height > LOCAL_576P_HEIGHT) || (!is50 && height > 483)) && !interlaced) {
        switch (frameRate) {
        case NEXUS_VideoFrameRate_e23_976:
        case NEXUS_VideoFrameRate_e24:
            return NEXUS_VideoFormat_e720p24hz;
        case NEXUS_VideoFrameRate_e25:
        case NEXUS_VideoFrameRate_e50:
            return NEXUS_VideoFormat_e720p50hz;
        default:
            return NEXUS_VideoFormat_e720p; /* 60hz */
        }
    }

    if (is50) {
        if (height == 288 && !interlaced) {
            /* handle one specific type */
            return NEXUS_VideoFormat_e288p50hz;
        }

        /* the catch all for 50Hz is 576i/576p */
       return interlaced ? NEXUS_VideoFormat_ePal : NEXUS_VideoFormat_e576p;
    }
    else {
        if (height == 240 && !interlaced) {
            /* handle one specific type */
            return NEXUS_VideoFormat_e240p60hz;
        }

        /* the catch all, if not 50Hz, is 480i/480p */
        return interlaced ? NEXUS_VideoFormat_eNtsc : NEXUS_VideoFormat_e480p;
    }
}

#ifndef USE_OCDM
/******************************************************************************
 * Function to display and handle the digital video output restrictions.
 ******************************************************************************/
static DRM_RESULT DRM_CALL handleDigitalVideoOutputProtectionIDs( __in const DRM_VIDEO_OUTPUT_PROTECTION_IDS_EX *f_pOPLs )
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_DWORD i;
    DRM_WCHAR rgwszGUID[DRM_GUID_STRING_LEN+1] = {0};
    DRM_CHAR  rgszGUID[DRM_NO_OF(rgwszGUID)] = {0};

    printf("    (%d entries)\r\n", f_pOPLs->cEntries );
    for( i = 0; i < f_pOPLs->cEntries; i++ )
    {
        ChkDR( DRM_UTL_GuidToString( &f_pOPLs->rgVop[i].guidId,
                            rgwszGUID ) );
        /* Safe to use, input parameter is in ASCII */
        DRM_UTL_DemoteUNICODEtoASCII( rgwszGUID, rgszGUID, DRM_NO_OF(rgwszGUID)-1 );

        printf("    GUID = %s\r\n", rgszGUID);

        if( 0 == MEMCMP( &f_pOPLs->rgVop[i].guidId, &g_guidMaxResDecode, sizeof( DRM_GUID ) ) )
        {
            DRM_DWORD           maxWidth;
            DRM_DWORD           maxHeight;
            NEXUS_VideoFormat   videoFormat;
            NxClient_DisplaySettings displaySettings;

            /* Hanlding MaxResDecode restriction.... */
            /* From CR 6.6.2:	A Binary Configuration Data Field for the MaxResDecode restriction must be defined as a set of two 32 bit values, each in Big Endian format.
            The first 32 bit field defines the Maximum Frame Width in Pixels, the second 32 bit field defines the Maximum Frame Height in Pixels */
            if (f_pOPLs->rgVop[i].cbConfigData != 8)  /*  (sizeof(maxWidth) + sizeof(maxHeight) */
            {
                printf("%s - at line %d configuration data size (%d) incorrect for MaxResDecode \n", __FUNCTION__, __LINE__, f_pOPLs->rgVop[i].cbConfigData);
                ChkDR(DRM_E_TEE_OUTPUT_PROTECTION_REQUIREMENTS_NOT_MET);
            }

            DRM_BIG_ENDIAN_BYTES_TO_NATIVE_DWORD(maxWidth,  f_pOPLs->rgVop[i].rgbConfigData);
            DRM_BIG_ENDIAN_BYTES_TO_NATIVE_DWORD(maxHeight, &f_pOPLs->rgVop[i].rgbConfigData[4]);

            BDBG_MSG(("%s - at line %d MaxResDecode restricts max width to %d pixels and max height to %d pixels", __FUNCTION__, __LINE__, maxWidth, maxHeight));

            NxClient_GetDisplaySettings(&displaySettings);
            /* Support for frame rate and interlacing parameters to determine the video format is a future consideration */
            videoFormat = getVideoFormatFromInfo(maxHeight, 0, 0);
            BDBG_MSG(("%s - at line %d setting video format = %d", __FUNCTION__, __LINE__, videoFormat));
            displaySettings.format = videoFormat;
            if ( NxClient_SetDisplaySettings(&displaySettings) != NEXUS_SUCCESS )
            {
                printf("%s - at line %d Error:  Could not update output display for MaxResDecode restriction\n", __FUNCTION__, __LINE__);
                ChkDR(DRM_E_FAIL);
            }
        }

    }
    printf("\r\n");
ErrorExit:
    return dr;
}

DRM_RESULT policy_callback(
    const DRM_VOID                 *f_pvPolicyCallbackData,
          DRM_POLICY_CALLBACK_TYPE  f_dwCallbackType,
    const DRM_KID   *f_pKID,
    const DRM_LID   *f_pLID,
    const DRM_VOID  *f_pv )
{
    DRM_RESULT dr = DRM_SUCCESS;
    const DRM_PLAY_OPL_EX2 *oplPlay = NULL;

    BSTD_UNUSED(f_pKID);
    BSTD_UNUSED(f_pLID);
    BSTD_UNUSED(f_pv);

    switch( f_dwCallbackType )
    {
        case DRM_PLAY_OPL_CALLBACK:
            printf("  Got DRM_PLAY_OPL_CALLBACK from Bind:\r\n");
            ChkArg( f_pvPolicyCallbackData != NULL );
            oplPlay = (const DRM_PLAY_OPL_EX2*)f_pvPolicyCallbackData;

            printf("    minOPL:\r\n");
            printf("    wCompressedDigitalVideo   = %d\r\n", oplPlay->minOPL.wCompressedDigitalVideo);
            printf("    wUncompressedDigitalVideo = %d\r\n", oplPlay->minOPL.wUncompressedDigitalVideo);
            printf("    wAnalogVideo              = %d\r\n", oplPlay->minOPL.wAnalogVideo);
            printf("    wCompressedDigitalAudio   = %d\r\n", oplPlay->minOPL.wCompressedDigitalAudio);
            printf("    wUncompressedDigitalAudio = %d\r\n", oplPlay->minOPL.wUncompressedDigitalAudio);
            printf("\r\n");

            printf("    oplIdReserved:\r\n");
            ChkDR( DRMTOOLS_PrintOPLOutputIDs( &oplPlay->oplIdReserved ) );

            printf("    vopi:\r\n");
            ChkDR( DRMTOOLS_PrintVideoOutputProtectionIDs( &oplPlay->vopi ) );

            printf("    dvopi:\r\n");
            ChkDR( handleDigitalVideoOutputProtectionIDs( &oplPlay->dvopi ) );

            break;

        case DRM_EXTENDED_RESTRICTION_QUERY_CALLBACK:
            {
                const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
                DRM_DWORD i = 0;

                printf("  Got DRM_EXTENDED_RESTRICTION_QUERY_CALLBACK from Bind:\r\n");

                printf("    wRightID = %d\r\n", pExtCallback->wRightID);
                printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
                printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

                printf("    Data     = ");

                for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
                {
                    printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
                }
                printf("\r\n\r\n");

                /* Report that restriction was not understood */
                dr = DRM_E_EXTENDED_RESTRICTION_NOT_UNDERSTOOD;
            }
            break;
        case DRM_EXTENDED_RESTRICTION_CONDITION_CALLBACK:
            {
                const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
                DRM_DWORD i = 0;

                printf("  Got DRM_EXTENDED_RESTRICTION_CONDITION_CALLBACK from Bind:\r\n");

                printf("    wRightID = %d\r\n", pExtCallback->wRightID);
                printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
                printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

                printf("    Data     = ");
                for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
                {
                    printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
                }
                printf("\r\n\r\n");
            }
            break;
        case DRM_EXTENDED_RESTRICTION_ACTION_CALLBACK:
            {
                const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT *pExtCallback = (const DRM_EXTENDED_RESTRICTION_CALLBACK_STRUCT*)f_pvPolicyCallbackData;
                DRM_DWORD i = 0;

                printf("  Got DRM_EXTENDED_RESTRICTION_ACTION_CALLBACK from Bind:\r\n");

                printf("    wRightID = %d\r\n", pExtCallback->wRightID);
                printf("    wType    = %d\r\n", pExtCallback->pRestriction->wType);
                printf("    wFlags   = %x\r\n", pExtCallback->pRestriction->wFlags);

                printf("    Data     = ");
                for( i = pExtCallback->pRestriction->ibData; (i - pExtCallback->pRestriction->ibData) < pExtCallback->pRestriction->cbData; i++ )
                {
                    printf("0x%.2X ", pExtCallback->pRestriction->pbBuffer[ i ] );
                }
                printf("\r\n\r\n");
            }
            break;
    default:
        printf("  Callback from Bind with unknown callback type of %d.\r\n", f_dwCallbackType);

        /* Report that this callback type is not implemented */
        ChkDR( DRM_E_NOTIMPL );
    }

ErrorExit:
    return dr;

}
#endif

#ifdef USE_OCDM
static OpenCDMSessionCallbacks _callbackImplementations;
#endif

uint8_t respBuffer[64*1024];
uint32_t respOffset = 0;
uint32_t respLength = sizeof(respBuffer);


void implementation_process_challenge (struct OpenCDMSession* /*session*/, void * userData, const char url[], const uint8_t challenge[], const uint16_t challengeLength) {


    uint8_t *pResponse = respBuffer;

    char* licenseURL = getenv("LA_URL");

    if (licenseURL == NULL) {
#ifdef OLD_PLAYREADY_SERVER
        licenseURL = "http://playready.directtaps.net/pr/svc/rightsmanager.asmx";
#else
        licenseURL = "http://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:150)";
#endif
    }
    printf("implementation_process_challenge: URL:%s challengeLength:%d\n",url,challengeLength);

    if(PRDY_HTTP_Client_LicensePostSoap(url, challenge, 1,
        150, (unsigned char**)&pResponse, (uint32_t*)&respOffset, (uint32_t*)&respLength) != 0) {
        BDBG_ERR(("PRDY_HTTP_Client_LicensePostSoap() failed, exiting"));
    }
    else {
        printf("%s - calling Drm_LicenseAcq_ProcessResponse SUCCEEDED\n", __FUNCTION__);
    }
}

void implementation_key_update (struct OpenCDMSession* /*session*/, void * userData, const uint8_t keyId[], const uint8_t length) {

    printf("%s - KEY UPDATE\n", __FUNCTION__);
}

void implementation_error_message (struct OpenCDMSession* /*session*/, void * userData, const char message[]) {
    printf("%s - MESSAGE %s\n", __FUNCTION__, message);
}

int playback_piff( NEXUS_SimpleVideoDecoderHandle videoDecoder,
                   NEXUS_SimpleAudioDecoderHandle audioDecoder,
                   PRDY_APP_CONTEXT         *pPrdyContext,
                   char *piff_file)
{
    int finalResult = -1;

#if SAGE_ENABLE
    uint8_t *pSecureVideoHeapBuffer = NULL;
    uint8_t *pSecureAudioHeapBuffer = NULL;
    pthread_t pthread;
    pthread_info *info = NULL;
    bool threadCreated = false;
#endif

    NEXUS_ClientConfiguration clientConfig;
    NEXUS_MemoryAllocationSettings memSettings;
    NEXUS_SimpleStcChannelHandle stcChannel;
    NEXUS_SimpleVideoDecoderStartSettings videoProgram;
    NEXUS_SimpleAudioDecoderStartSettings audioProgram;
    NEXUS_PlaypumpOpenSettings videoplaypumpOpenSettings;
    NEXUS_PlaypumpOpenSettings audioplaypumpOpenSettings;
    NEXUS_SimpleStcChannelSettings stcSettings;
    NEXUS_PlaypumpSettings playpumpSettings;
    NEXUS_Error rc;
    CommonCryptoHandle commonCryptoHandle = NULL;
    CommonCryptoSettings  cmnCryptoSettings;

    NEXUS_DisplayHandle display = NULL;
    NEXUS_PidChannelHandle videoPidChannel = NULL;
    BKNI_EventHandle event = NULL;
    NEXUS_PlaypumpHandle videoPlaypump = NULL;
    NEXUS_PlaypumpHandle audioPlaypump = NULL;

    NEXUS_PidChannelHandle audioPidChannel = NULL;

    app_ctx app;
    bool moovBoxParsed = false;

    uint8_t resp_buffer[64*1024];
    char *pCh_url = NULL;
    uint8_t *pCh_data = NULL;
    uint8_t *pResponse = resp_buffer;
    uint32_t respLen;
    uint32_t respOffset;
    uint32_t urlLen;
    uint32_t chLen;
    piff_parser_handle_t piff_handle;
    bfile_io_read_t fd;
    uint8_t *pssh_data;
    size_t pssh_len;
    NEXUS_PlaypumpOpenPidChannelSettings video_pid_settings;

    if(piff_file == NULL ) {
        goto ErrorExit;
    }

#if SAGE_ENABLE
    info = (pthread_info *)BKNI_Malloc(sizeof(pthread_info));
#endif

    BDBG_MSG(("PIFF file: %s\n",piff_file));
    fflush(stdout);

    BKNI_Memset(&app, 0, sizeof( app_ctx));
    app.last_video_fragment_time = 0;
    app.last_audio_fragment_time = 0;

    app.fp_piff = fopen(piff_file, "rb");
    if(app.fp_piff == NULL){
        fprintf(stderr,"failed to open %s\n", piff_file);
        goto ErrorExit;
    }

    fd = bfile_stdio_read_attach(app.fp_piff);

    piff_handle = piff_parser_create(fd);
    if (!piff_handle) {
        BDBG_ERR(("Unable to create PIFF parser context"));
        goto ErrorExit;
    }

    fseek(app.fp_piff, 0, SEEK_END);
    app.piff_filesize = ftell(app.fp_piff);
    fseek(app.fp_piff, 0, SEEK_SET);

    if( pPrdyContext == NULL)
    {
       BDBG_ERR(("pPrdyContext is NULL, quitting...."));
       goto ErrorExit ;
    }

    CommonCrypto_GetDefaultSettings(&cmnCryptoSettings);
    commonCryptoHandle = CommonCrypto_Open(&cmnCryptoSettings);

    NEXUS_Platform_GetClientConfiguration(&clientConfig);
    NEXUS_Memory_GetDefaultAllocationSettings(&memSettings);
    memSettings.heap = clientConfig.heap[1]; /* heap 1 is the eFull heap for the nxclient. */

    /* Show heaps info */
    {
        int g;
        BDBG_MSG(("NxClient Heaps Info -----------------"));
        for (g = NXCLIENT_DEFAULT_HEAP; g <= NXCLIENT_SECONDARY_GRAPHICS_HEAP; g++)
        {
            NEXUS_MemoryStatus status;
            NEXUS_Heap_GetStatus(clientConfig.heap[g], &status);

            BDBG_MSG(("Heap[%d]: memoryType=%u, heapType=%u, offset=%u, addr=%p, size=%u",
                      g, status.memoryType, status.heapType, (uint32_t)status.offset, status.addr, status.size));
        }
        BDBG_MSG(("-------------------------------------"));
    }

    if( NEXUS_Memory_Allocate(BUF_SIZE, &memSettings, (void **)&app.pPayload) !=  NEXUS_SUCCESS) {
        fprintf(stderr,"NEXUS_Memory_Allocate failed");
        goto ErrorExit;
    }

    if( NEXUS_Memory_Allocate(BUF_SIZE, &memSettings, (void **)&app.pOutBuf) !=  NEXUS_SUCCESS) {
        fprintf(stderr,"NEXUS_Memory_Allocate failed");
        goto ErrorExit;
    }

    /* Perform parsing of the movie information */
    moovBoxParsed = piff_parser_scan_movie_info(piff_handle);
    if(!moovBoxParsed) {
        BDBG_ERR(("Failed to parse moov box, can't continue..."));
        goto ErrorExit;
    }

    BDBG_MSG(("Successfully parsed the moov box, continue...\n\n"));

    /* EXTRACT AND PLAYBACK THE MDAT */

    NEXUS_Playpump_GetDefaultOpenSettings(&videoplaypumpOpenSettings);
    videoplaypumpOpenSettings.fifoSize *= 7;
    videoplaypumpOpenSettings.numDescriptors *= 7;

#if SAGE_ENABLE
    info->videoDecoder = videoDecoder;
    videoplaypumpOpenSettings.dataNotCpuAccessible = true;
    pSecureVideoHeapBuffer = SRAI_Memory_Allocate(videoplaypumpOpenSettings.fifoSize,
            SRAI_MemoryType_SagePrivate);
    if ( pSecureVideoHeapBuffer == NULL ) {
        BDBG_ERR((" Failed to allocate from Secure Video heap"));
        BDBG_ASSERT( false );
    }
    videoplaypumpOpenSettings.memory = NEXUS_MemoryBlock_FromAddress(pSecureVideoHeapBuffer);
#else
    videoplaypumpOpenSettings.heap = clientConfig.heap[1];
    videoplaypumpOpenSettings.boundsHeap = clientConfig.heap[1];
#endif

    videoPlaypump = NEXUS_Playpump_Open(NEXUS_ANY_ID, &videoplaypumpOpenSettings);
    if (!videoPlaypump) {
        BDBG_ERR(("@@@ Video Playpump Open FAILED----"));
        goto ErrorExit;
    }
    BDBG_ASSERT(videoPlaypump != NULL);

#if SAGE_ENABLE
    NEXUS_Playpump_GetDefaultOpenSettings(&audioplaypumpOpenSettings);
    audioplaypumpOpenSettings.dataNotCpuAccessible = true;
    pSecureAudioHeapBuffer = SRAI_Memory_Allocate(audioplaypumpOpenSettings.fifoSize,
            SRAI_MemoryType_SagePrivate);
    if ( pSecureAudioHeapBuffer == NULL ) {
        BDBG_ERR((" Failed to allocate from Secure Audio heap"));
        goto ErrorExit;
    }
    BDBG_ASSERT( pSecureAudioHeapBuffer != NULL );
    audioplaypumpOpenSettings.memory = NEXUS_MemoryBlock_FromAddress(pSecureAudioHeapBuffer);
#else
    NEXUS_Playpump_GetDefaultOpenSettings(&audioplaypumpOpenSettings);
    audioplaypumpOpenSettings.heap = clientConfig.heap[1];
    audioplaypumpOpenSettings.boundsHeap = clientConfig.heap[1];
#endif

    audioPlaypump = NEXUS_Playpump_Open(NEXUS_ANY_ID, &audioplaypumpOpenSettings);
    if (!audioPlaypump) {
        BDBG_ERR(("@@@ Audio Playpump Open FAILED----"));
        goto ErrorExit;
    }
    BDBG_ASSERT(audioPlaypump != NULL);

    stcChannel = NEXUS_SimpleStcChannel_Create(NULL);
    NEXUS_SimpleStcChannel_GetSettings(stcChannel, &stcSettings);
    stcSettings.mode = NEXUS_StcChannelMode_eAuto;
    rc = NEXUS_SimpleStcChannel_SetSettings(stcChannel, &stcSettings);
    if (rc) {
       BDBG_WRN(("@@@ Stc Set FAILED ---------------"));
    }

    BKNI_CreateEvent(&event);

    NEXUS_Playpump_GetSettings(videoPlaypump, &playpumpSettings);
    playpumpSettings.dataCallback.callback = play_callback;
    playpumpSettings.dataCallback.context = event;
    playpumpSettings.transportType = NEXUS_TransportType_eMpeg2Pes;
    NEXUS_Playpump_SetSettings(videoPlaypump, &playpumpSettings);

    NEXUS_Playpump_GetSettings(audioPlaypump, &playpumpSettings);
    playpumpSettings.dataCallback.callback = play_callback;
    playpumpSettings.dataCallback.context = event;
    playpumpSettings.transportType = NEXUS_TransportType_eMpeg2Pes;
    NEXUS_Playpump_SetSettings(audioPlaypump, &playpumpSettings);

    /* already connected in main */
    NEXUS_SimpleAudioDecoder_GetDefaultStartSettings(&audioProgram);
    NEXUS_SimpleVideoDecoder_GetDefaultStartSettings(&videoProgram);

    NEXUS_Playpump_Start(videoPlaypump);
    NEXUS_Playpump_Start(audioPlaypump);

    NEXUS_Playpump_GetDefaultOpenPidChannelSettings(&video_pid_settings);
    video_pid_settings.pidType = NEXUS_PidType_eVideo;

    videoPidChannel = NEXUS_Playpump_OpenPidChannel(videoPlaypump, REPACK_VIDEO_PES_ID, &video_pid_settings);
#if SAGE_ENABLE
    NEXUS_SetPidChannelBypassKeyslot(videoPidChannel, NEXUS_BypassKeySlot_eGR2R);
#endif

    if ( !videoPidChannel )
      BDBG_WRN(("@@@ videoPidChannel NULL"));
    else
      BDBG_WRN(("@@@ videoPidChannel OK"));

    audioPidChannel = NEXUS_Playpump_OpenPidChannel(audioPlaypump, REPACK_AUDIO_PES_ID, NULL);
#if SAGE_ENABLE
    NEXUS_SetPidChannelBypassKeyslot(audioPidChannel, NEXUS_BypassKeySlot_eGR2R);
#endif

    if ( !audioPidChannel )
      BDBG_WRN(("@@@ audioPidChannel NULL"));
    else
      BDBG_WRN(("@@@ audioPidChannel OK"));

    NEXUS_SimpleAudioDecoder_GetDefaultStartSettings(&audioProgram);
    NEXUS_SimpleVideoDecoder_GetDefaultStartSettings(&videoProgram);

    if ( vc1_stream ) {
       BDBG_MSG(("@@@ set video audio program for vc1"));
       videoProgram.settings.codec = NEXUS_VideoCodec_eVc1;
       audioProgram.primary.codec = NEXUS_AudioCodec_eWmaPro;
    } else {
       BDBG_MSG(("@@@ set video audio program for h264"));
       videoProgram.settings.codec = NEXUS_VideoCodec_eH264;
       audioProgram.primary.codec = NEXUS_AudioCodec_eAacAdts;
    }

    videoProgram.settings.pidChannel = videoPidChannel;
    NEXUS_SimpleVideoDecoder_Start(videoDecoder, &videoProgram);

    audioProgram.primary.pidChannel = audioPidChannel;
    NEXUS_SimpleAudioDecoder_Start(audioDecoder, &audioProgram);

    if (videoProgram.settings.pidChannel) {
        BDBG_WRN(("@@@ set stc channel video"));
        NEXUS_SimpleVideoDecoder_SetStcChannel(videoDecoder, stcChannel);
    }

    if (audioProgram.primary.pidChannel) {
        BDBG_WRN(("@@@ set stc channel audio"));
        NEXUS_SimpleAudioDecoder_SetStcChannel(audioDecoder, stcChannel);
    }

    /***********************
     * now ready to decrypt
     ***********************/
    pssh_data = piff_parser_get_pssh(piff_handle, &pssh_len);
    if (!pssh_data) {
        BDBG_ERR(("Failed to obtain pssh data"));
        goto ErrorExit;
    }

    int aa;
    for(int aa=0; aa<pssh_len; ++aa)
        printf("%X ",pssh_data[aa]);
    printf("\n");
#ifdef USE_OCDM
    printf("%s - calling OCDM to setup decrypt session\n", __FUNCTION__);

    /* Abuse the void* pointer to hold a session we can use for PlayReady decrypt over the OCDM. */
    // TODO: Use WideVine or Playready depending on the asset WideVine
    const char keySystem[] = "com.microsoft.playready";
    printf("%s - calling OCDM to create system(%s)\n", __FUNCTION__, keySystem);
    OpenCDMError result = opencdm_create_system_extended(keySystem, &pPrdyContext->pDrmAppCtx);
    if(result != ERROR_NONE)
    {
        printf("%s - calling OCDM: create system(%s) failed(0x%X)\n", __FUNCTION__, keySystem, result);
    }

    struct OpenCDMSession* session = NULL;
    if (opencdm_construct_session(pPrdyContext->pDrmAppCtx,
                               PersistentLicense,
                               "None",
                               pssh_data, (uint16_t)pssh_len,
                               NULL, 0,
                               &_callbackImplementations,
                               NULL, /*TODO: double check if the userData needs to bee filled in or not */
                               &session) != 0) {

        printf("%s - calling opencdm_create_session FAILED !!!\n", __FUNCTION__);
    }
    else if (session == NULL) {
        printf("%s - calling opencdm_create_session did NOT result in a session !!!\n", __FUNCTION__);
    }
    else {
        if (opencdm_session_update(session, &(respBuffer[respOffset]), respLength) != 0) {
            printf("%s - calling Drm_LicenseAcq_ProcessResponse FAILED !!!!\n", __FUNCTION__);
        }
        printf("DRM Session setup and running !!!!!\n");
    }

    pPrdyContext->pOEMContext = session;
    app.decryptor = session;


#else
    printf("%s - calling Drm_Content_SetProperty\n", __FUNCTION__);

    DRM_RESULT dr;

    DRM_DWORD dwEncryptionMode  = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
    DRM_CHAR *pszCustomDataUsed = NULL;
    DRM_DWORD cchCustomDataUsed = 0;
    const DRM_CONST_STRING *rgstrRights[ 1 ] = { &g_dstrWMDRM_RIGHT_PLAYBACK };
    uint8_t                *pbNewOpaqueBuffer = NULL;
    uint32_t cbNewOpaqueBuffer = pPrdyContext->cbOpaqueBuffer * 2;
    DRM_LICENSE_RESPONSE oResponse;

    ChkDR (Drm_Content_SetProperty(pPrdyContext->pDrmAppCtx,
                                   DRM_CSP_AUTODETECT_HEADER,
                                   pssh_data,
                                   (uint32_t)pssh_len ));


    /* set encryption/decryption mode */
    dwEncryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
    dr = Drm_Content_SetProperty(
        pPrdyContext->pDrmAppCtx,
        DRM_CSP_DECRYPTION_OUTPUT_MODE,
        (const DRM_BYTE*)&dwEncryptionMode,
        sizeof( DRM_DWORD ) ) ;
    if ( dr != DRM_SUCCESS ) {
        BDBG_ERR(("Drm_Content_SetProperty() failed, exiting"));
        goto ErrorExit;
    }


    printf("%s - calling Drm_LicenseAcq_GenerateChallenge\n", __FUNCTION__);
    dr = Drm_LicenseAcq_GenerateChallenge(
            pPrdyContext->pDrmAppCtx,
            rgstrRights,
            sizeof(rgstrRights)/sizeof(DRM_CONST_STRING*), /*1,*/
            NULL,
            pszCustomDataUsed,
            cchCustomDataUsed,
            NULL,
            (DRM_DWORD*)&urlLen,
            NULL,
            NULL,
            NULL,
            (DRM_DWORD*)&chLen,
            NULL);

    if ( dr != DRM_E_BUFFERTOOSMALL ) {
        BDBG_ERR(("Drm_LicenseAcq_GenerateChallenge() failed, exiting"));
        goto ErrorExit;
    }

    pCh_url = ( char *)BKNI_Malloc(urlLen);
    if(pCh_url == NULL) {
        BDBG_ERR(("BKNI_Malloc(urlent) failed, exiting..."));
        goto ErrorExit;
    }

    pCh_data = (uint8_t *)BKNI_Malloc(chLen);
    if(pCh_data == NULL) {
        BDBG_ERR(("BKNI_Malloc(chLen) failed, exiting..."));
        goto ErrorExit;
    }

    printf("%s - calling Drm_LicenseAcq_GenerateChallenge 2\n", __FUNCTION__);
    ChkDR( Drm_LicenseAcq_GenerateChallenge(
                pPrdyContext->pDrmAppCtx,
                rgstrRights,
                sizeof(rgstrRights)/sizeof(DRM_CONST_STRING*), /*1,*/
                NULL,
                pszCustomDataUsed,
                cchCustomDataUsed,
                pCh_url,
                (DRM_DWORD*) &urlLen, /*(pUrl_len>0)?&cchURL:NULL, */
                NULL,
                NULL,
                (DRM_BYTE*)pCh_data,
                (DRM_DWORD*)&chLen,
                NULL));

    pCh_data[ chLen ] = 0;

    char* licenseURL = getenv("LA_URL");

    if (licenseURL == NULL) {
#ifdef OLD_PLAYREADY_SERVER
        licenseURL = "http://playready.directtaps.net/pr/svc/rightsmanager.asmx";
#else
        licenseURL = "http://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:150)";
#endif
    }

    if(PRDY_HTTP_Client_LicensePostSoap(licenseURL, pCh_data, 1,
        150, (unsigned char **)&pResponse, (uint32_t*)&respOffset, (uint32_t*)&respLen) != 0) {
        BDBG_ERR(("PRDY_HTTP_Client_LicensePostSoap() failed, exiting"));
        goto ErrorExit;
    }

    printf("%s - calling Drm_LicenseAcq_ProcessResponse\n", __FUNCTION__);
    BKNI_Memset( &oResponse, 0, sizeof( DRM_LICENSE_RESPONSE ) );

    printf("HTTP :: resp_len <%d> and offset<%d>, buf<%s>\n", respLen, respOffset, pResponse);

    dr =  Drm_LicenseAcq_ProcessResponse(
            pPrdyContext->pDrmAppCtx,
            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
            (const uint8_t * )&pResponse[respOffset],
            respLen,
            &oResponse );
    printf("%s - calling Drm_LicenseAcq_ProcessResponse done, dr = %x\n", __FUNCTION__, (unsigned int)dr);
    ChkDR(dr);


    printf("%s - calling Drm_Reader_Bind\n", __FUNCTION__);
    while( (dr = Drm_Reader_Bind(
                    pPrdyContext->pDrmAppCtx,
                    rgstrRights,
                    1,
                    (DRMPFNPOLICYCALLBACK)policy_callback,
                    (void *) pPrdyContext,
                    (DRM_DECRYPT_CONTEXT *)  &app.decryptor)) == DRM_E_BUFFERTOOSMALL)
    {
        BDBG_ASSERT( cbNewOpaqueBuffer > pPrdyContext->cbOpaqueBuffer ); /* overflow check */

        if( cbNewOpaqueBuffer > DRM_MAXIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE )
        {
            ChkDR( DRM_E_OUTOFMEMORY );
        }

        ChkMem( pbNewOpaqueBuffer = ( uint8_t* )Oem_MemAlloc( cbNewOpaqueBuffer ) );

        ChkDR( Drm_ResizeOpaqueBuffer(
                    pPrdyContext->pDrmAppCtx,
                    pbNewOpaqueBuffer,
                    cbNewOpaqueBuffer ) );

        /*
         Free the old buffer and then transfer the new buffer ownership
         Free must happen after Drm_ResizeOpaqueBuffer because that
         function assumes the existing buffer is still valid
        */
        SAFE_OEM_FREE( pPrdyContext->pbOpaqueBuffer );
        pPrdyContext->cbOpaqueBuffer = cbNewOpaqueBuffer;
        pPrdyContext->pbOpaqueBuffer = pbNewOpaqueBuffer;
        pbNewOpaqueBuffer = NULL;
    }

    printf("%s - calling Drm_Reader_Bind dr %x\n", __FUNCTION__, (unsigned int)dr);

    if (DRM_FAILED( dr )) {
        if (dr == DRM_E_LICENSE_NOT_FOUND) {
            /* could not find a license for the KID */
            BDBG_ERR(("%s: no licenses found in the license store. Please request one from the license server.\n", __FUNCTION__));
        }
        else if(dr == DRM_E_LICENSE_EXPIRED) {
            /* License is expired */
            BDBG_ERR(("%s: License expired. Please request one from the license server.\n", __FUNCTION__));
        }
        else if(  dr == DRM_E_RIV_TOO_SMALL ||
                  dr == DRM_E_LICEVAL_REQUIRED_REVOCATION_LIST_NOT_AVAILABLE )
        {
            /* Revocation Package must be update */
            BDBG_ERR(("%s: Revocation Package must be update. 0x%x\n", __FUNCTION__,(unsigned int)dr));
        }
        else {
            BDBG_ERR(("%s: unexpected failure during bind. 0x%x\n", __FUNCTION__,(unsigned int)dr));
        }
    }

    printf("%s - calling Drm_Reader_Commit dr %x\n", __FUNCTION__, (unsigned int)dr);
    ChkDR( Drm_Reader_Commit( pPrdyContext->pDrmAppCtx, NULL, NULL ) );
    printf("%s - calling Drm_Reader_Commit dr %x\n", __FUNCTION__, (unsigned int)dr);
#endif

    printf("**** FSeek\n");
    /* now go back to the begining and get all the moof boxes */
    fseek(app.fp_piff, 0, SEEK_END);
    app.piff_filesize = ftell(app.fp_piff);
    fseek(app.fp_piff, 0, SEEK_SET);

    video_decode_hdr = 0;
#if SAGE_ENABLE
    rc = pthread_create(&pthread, NULL, check_buffer, (void *)info);
    if (rc)
    {
        BDBG_ERR(("return code from pthread_create() is %d\n", rc));
        ChkDR(DRM_E_FAIL);
    }

    threadCreated = true;
#endif
    /* Start parsing the the file to look for MOOFs and MDATs */
    while(!feof(app.fp_piff))
    {
        piff_parse_frag_info frag_info;
        void *decoder_data;
        size_t decoder_len;

        if (!piff_parser_scan_movie_fragment(piff_handle, &frag_info, app.pPayload, BUF_SIZE)) {
            if (feof(app.fp_piff)) {
                BDBG_WRN(("Reached EOF"));
                break;
            } else {
                BDBG_ERR(("Unable to parse movie fragment"));
                goto ErrorExit;
            }
        }
        decoder_data = piff_parser_get_dec_data(piff_handle, &decoder_len, frag_info.trackId);

#if SAGE_ENABLE
        if (frag_info.trackType == BMP4_SAMPLE_ENCRYPTED_VIDEO) {
            DRM_RESULT result = secure_process_fragment(commonCryptoHandle, &app, &frag_info, (frag_info.mdat_size - BOX_HEADER_SIZE),
                    decoder_data, decoder_len, videoPlaypump, event);
            if(result)
            {
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] secure_process_fragment failed with %d\n", __FILE__, __LINE__, __FUNCTION__, result);
            }

        } else if (frag_info.trackType == BMP4_SAMPLE_ENCRYPTED_AUDIO) {
            DRM_RESULT result = secure_process_fragment(commonCryptoHandle, &app, &frag_info, (frag_info.mdat_size - BOX_HEADER_SIZE),
                    decoder_data, decoder_len, audioPlaypump, event);
            if(result)
            {
                fprintf(stderr, "***AG-PRINT*[%s:%d %s()] secure_process_fragment failed with %d\n", __FILE__, __LINE__, __FUNCTION__, result);
            }
        }
#else
        if(process_fragment(commonCryptoHandle, &app, &frag_info, (frag_info.mdat_size - BOX_HEADER_SIZE),
                    decoder_data, decoder_len) == 0) {
            if (frag_info.trackType == BMP4_SAMPLE_ENCRYPTED_VIDEO) {
                send_fragment_data(commonCryptoHandle, app.pOutBuf, app.outBufSize,
                        videoPlaypump, event);

            } else if (frag_info.trackType == BMP4_SAMPLE_ENCRYPTED_AUDIO) {
                send_fragment_data(commonCryptoHandle, app.pOutBuf, app.outBufSize,
                        audioPlaypump, event);
            }
        }
#endif /* #if SAGE_ENABLE */

    } /* while */

ErrorExit:
    printf("**** ERROR\n");
    complete_play_fragments(audioDecoder, videoDecoder, videoPlaypump,
            audioPlaypump, display, audioPidChannel, videoPidChannel, NULL, event);
    if(stcChannel) NEXUS_SimpleStcChannel_Destroy(stcChannel);

#if SAGE_ENABLE
    if(threadCreated && pthread){
        if(pthread_join(pthread, (void**) &info) != 0)
        {
            BDBG_ERR(("ERROR IN PTHREAD_JOIN"));
            goto ErrorExit;
        } else {
            finalResult = info->result;
        }
        if (info->result == 0) {
            BDBG_LOG(("Success!"));
        } else {
            BDBG_ERR(("ERROR: thread failed"));
        }
    }
#endif

#ifndef USE_OCDM
    if(pbNewOpaqueBuffer) Oem_MemFree(pbNewOpaqueBuffer);

    if( (*((uint8_t *)&app.decryptor)) ) Drm_Reader_Close( &app.decryptor);
#endif

    if(pCh_data != NULL) BKNI_Free(pCh_data);
    if(pCh_url != NULL) BKNI_Free(pCh_url);
#if SAGE_ENABLE
    if(pSecureAudioHeapBuffer) SRAI_Memory_Free(pSecureAudioHeapBuffer);
    if(pSecureVideoHeapBuffer) SRAI_Memory_Free(pSecureVideoHeapBuffer);
    if(info != NULL) BKNI_Free(info);
#endif
    if(app.pOutBuf) NEXUS_Memory_Free(app.pOutBuf);
    if(app.pPayload) NEXUS_Memory_Free(app.pPayload);

    if(commonCryptoHandle) CommonCrypto_Close(commonCryptoHandle);

    if(piff_handle != NULL) piff_parser_destroy(piff_handle);

    bfile_stdio_read_detach(fd);
    if(app.fp_piff) fclose(app.fp_piff);

    return finalResult;
}

#ifndef USE_OCDM

#define MAX_TIME_CHALLENGE_RESPONSE_LENGTH (1024*64)
#define MAX_URL_LENGTH (512)
int initSecureClock( DRM_APP_CONTEXT *pDrmAppCtx)
{
    int                   rc = 0;
    DRM_DWORD             cbChallenge     = 0;
    DRM_BYTE             *pbChallenge     = NULL;
    DRM_BYTE             *pbResponse      = NULL;
    char                 *pTimeChallengeURL = NULL;
    char                  secureTimeUrlStr[MAX_URL_LENGTH];
    bool                  redirect = true;
    int32_t               petRC=0;
    uint32_t              petRespCode = 0;
    uint32_t              startOffset;
    uint32_t              length;
    uint32_t              post_ret;
    NEXUS_MemoryAllocationSettings allocSettings;
    DRM_RESULT            drResponse = DRM_SUCCESS;
    DRM_RESULT            dr = DRM_SUCCESS;

    dr = Drm_SecureTime_GenerateChallenge( pDrmAppCtx,
                                           &cbChallenge,
                                           &pbChallenge );
    ChkDR(dr);

    NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);
    rc = NEXUS_Memory_Allocate(MAX_URL_LENGTH, &allocSettings, (void **)(&pTimeChallengeURL ));
    if(rc != NEXUS_SUCCESS)
    {
        BDBG_ERR(("%s - %d NEXUS_Memory_Allocate failed for time challenge response buffer, rc = %d\n",__FUNCTION__, __LINE__, rc));
        goto ErrorExit;
    }

    /* send the petition request to Microsoft with HTTP GET */
    petRC = PRDY_HTTP_Client_GetForwardLinkUrl(g_dstrHttpSecureTimeServerUrl.pszString,
                                               &petRespCode,
                                               (char**)&pTimeChallengeURL);

    if( petRC != 0)
    {
       BDBG_ERR(("%d Secure Time forward link petition request failed, rc = %d\n",__LINE__, petRC));
       rc = petRC;
       goto ErrorExit;
    }

    do
    {
        redirect = false;

        /* we need to check if the Pettion responded with redirection */
        if( petRespCode == 200)
        {
            redirect = false;
        }
        else if( petRespCode == 302 || petRespCode == 301)
        {
            redirect = true;
            memset(secureTimeUrlStr, 0, MAX_URL_LENGTH);
            strcpy(secureTimeUrlStr, pTimeChallengeURL);
            memset(pTimeChallengeURL, 0, MAX_URL_LENGTH);

            petRC = PRDY_HTTP_Client_GetSecureTimeUrl(secureTimeUrlStr,
                                                      &petRespCode,
                                                      (char**)&pTimeChallengeURL);

            if( petRC != 0)
            {
               BDBG_ERR(("%d Secure Time URL petition request failed, rc = %d\n",__LINE__, petRC));
               rc = petRC;
               goto ErrorExit;
            }
        }
        else
        {
           BDBG_ERR(("%d Secure Clock Petition responded with unsupported result, rc = %d, can't get the time challenge URL\n",__LINE__, petRespCode));
           rc = -1;
           goto ErrorExit;
        }
    } while (redirect);

    NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);
    rc = NEXUS_Memory_Allocate(MAX_TIME_CHALLENGE_RESPONSE_LENGTH, &allocSettings, (void **)(&pbResponse ));
    if(rc != NEXUS_SUCCESS)
    {
        BDBG_ERR(("%d NEXUS_Memory_Allocate failed for time challenge response buffer, rc = %d\n",__LINE__, rc));
        goto ErrorExit;
    }

    BKNI_Memset(pbResponse, 0, MAX_TIME_CHALLENGE_RESPONSE_LENGTH);
    post_ret = PRDY_HTTP_Client_SecureTimeChallengePost(pTimeChallengeURL,
                                                 (char *)pbChallenge,
                                                 1,
                                                 150,
                                                 (unsigned char**)&(pbResponse),
                                                 &startOffset,
                                                 &length);
    if( post_ret != 0)
    {
        BDBG_ERR(("%d Secure Time Challenge request failed, rc = %d\n",__LINE__, post_ret));
        rc = post_ret;
        goto ErrorExit;
    }

    drResponse = Drm_SecureTime_ProcessResponse(
                                    pDrmAppCtx,
                                    length,
                                    (uint8_t *) pbResponse);
    if ( drResponse != DRM_SUCCESS )
    {
       BDBG_ERR(("%s - %d Drm_SecureTime_ProcessResponse failed, drResponse = %x\n",__FUNCTION__, __LINE__, (unsigned int)drResponse));
       dr = drResponse;
       ChkDR( drResponse);

    }
    BDBG_LOG(("%d Initialized Playready Secure Clock success.",__LINE__));

    /* NOW testing the system time */

ErrorExit:

    ChkVOID( SAFE_OEM_FREE( pbChallenge ) );

    if( pTimeChallengeURL    != NULL)
        NEXUS_Memory_Free(pTimeChallengeURL  );

    if( pbResponse != NULL )
        NEXUS_Memory_Free(pbResponse);

    return rc;
}
#endif

int start(int argc, char* argv[])
{
    printf("**** START\n");
    NxClient_JoinSettings joinSettings;
    NxClient_AllocSettings allocSettings;
    NxClient_AllocResults allocResults;
    NEXUS_Error rc;
    int ret = -1;

    NEXUS_ClientConfiguration clientConfig;
    NxClient_ConnectSettings connectSettings;
    unsigned connectId;
    NEXUS_SurfaceClientHandle surfaceClient = NULL;
    NEXUS_SurfaceClientHandle videoSurfaceClient = NULL;
    NEXUS_SimpleVideoDecoderHandle videoDecoder = NULL;
    NEXUS_SimpleAudioDecoderHandle audioDecoder = NULL;

#ifdef ANDROID
    NEXUS_SurfaceComposition comp;
    NEXUS_VideoFormatInfo videoInfo;
    NEXUS_VideoDecoderCapabilities caps;
    uint32_t maxDecoderWidth = 1920;
    uint32_t maxDecoderHeight = 1080;
    int i;
#endif

    printf("**** ARGPARSE\n");
    if (argc < 2) {
        BDBG_ERR(("Usage : %s <input_file> [-vc1]", argv[0]));
        return -1;
    }

    while(argc>2)
    {
        argc--;
        if(strcmp(argv[argc], "-vc1") == 0)
        {
            printf("%s - vc1_stream found\n", __FUNCTION__);
            vc1_stream = 1;
        }
        else
        {
            BDBG_ERR(("Unrecognized option: %s", argv[argc]));
        }
    }


    BDBG_MSG(("@@@ MSG Check Point Start vc1_stream %d--", vc1_stream));

    printf("**** NEXUS JOIN\n");
    NxClient_GetDefaultJoinSettings(&joinSettings);
    snprintf(joinSettings.name, NXCLIENT_MAX_NAME, "pr_piff_playback");
    rc = NxClient_Join(&joinSettings);
    if (rc)
    {
        BDBG_ERR(("Error in NxClient_Join"));
        return -1;
    }
    printf("**** HEAP PRINT\n");
    /* print heaps on server side */
    NEXUS_Memory_PrintHeaps();

#ifdef ANDROID
    /* Request for Secure heap for secure decoder */
    (void)setupRuntimeHeaps( true, true );
#endif
    printf("**** NEXUS ALLOC\n");
    NxClient_GetDefaultAllocSettings(&allocSettings);
    allocSettings.simpleVideoDecoder = 1;
    allocSettings.simpleAudioDecoder = 1;
    allocSettings.surfaceClient = 1;
    rc = NxClient_Alloc(&allocSettings, &allocResults);
    if (rc)
    {
        BDBG_ERR(("Error in NxClient_Alloc"));
        goto ErrorExit;
    }

    PRDY_APP_CONTEXT     prdyCtx;

#ifdef USE_OCDM
    _callbackImplementations.process_challenge_callback = implementation_process_challenge;
    _callbackImplementations.key_update_callback = implementation_key_update;
    _callbackImplementations.error_message_callback = implementation_error_message;
#else
    printf("**** PLAYREADY INIT\n");
    /* DRM_Prdy specific */
    DRM_RESULT           dr = DRM_SUCCESS;
    OEM_Settings         oemSettings;
    DRM_BYTE            *pbRevocationBuffer = NULL;

    DRM_WCHAR           *hdsDir = bdrm_get_hds_dir();
    DRM_WCHAR           *hdsFname = bdrm_get_pr3x_hds_fname();

    DRM_CONST_STRING   sDstrHDSPath = DRM_EMPTY_DRM_STRING;
    DRM_WCHAR          sRgwchHDSPath[ DRM_MAX_PATH ];

    DRMFILETIME               ftSystemTime; /* Initialized by Drm_SecureTime_GetValue */
    DRM_SECURETIME_CLOCK_TYPE eClockType;   /* Initialized by Drm_SecureTime_GetValue */

    BKNI_Memset(&oemSettings, 0, sizeof(oemSettings));
    oemSettings.binFileName = NULL;
    oemSettings.keyHistoryFileName = NULL;

    /* initialize the DRM_APP_CONTEXT */
    BKNI_Memset(&prdyCtx, 0, sizeof(prdyCtx));

    prdyCtx.pDrmAppCtx = (DRM_APP_CONTEXT*)Oem_MemAlloc(sizeof(DRM_APP_CONTEXT));
    ChkMem(prdyCtx.pDrmAppCtx);
    BKNI_Memset(( uint8_t * )prdyCtx.pDrmAppCtx, 0, sizeof( DRM_APP_CONTEXT));

    NEXUS_Platform_GetClientConfiguration(&clientConfig);
    oemSettings.heap = clientConfig.heap[1]; /* heap 1 is the eFull heap for the nxclient. */

    printf("**** DRM INITIALIZE\n");
    dr = Drm_Platform_Initialize((void *)&oemSettings);
    ChkDR(dr);

    prdyCtx.pOEMContext = oemSettings.f_pOEMContext;
    ChkMem(prdyCtx.pOEMContext);
    printf("%s - prdyCtx.pOEMContext %p\n", __FUNCTION__, prdyCtx.pOEMContext);

    /* Initialize OpaqueBuffer and RevocationBuffer */
    prdyCtx.cbOpaqueBuffer = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;
    ChkMem( prdyCtx.pbOpaqueBuffer = ( uint8_t * )Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE));
    ChkMem( pbRevocationBuffer = ( uint8_t * )Oem_MemAlloc( REVOCATION_BUFFER_SIZE));

    /* Drm_Initialize */
    sDstrHDSPath.pwszString = sRgwchHDSPath;
    sDstrHDSPath.cchString = DRM_MAX_PATH;

    /* Convert the HDS path to DRM_STRING. */

    if (bdrm_get_hds_dir_lgth() > 0){
        BKNI_Memcpy((DRM_WCHAR*)sDstrHDSPath.pwszString, hdsDir, bdrm_get_hds_dir_lgth() * sizeof(DRM_WCHAR));
    }
    BKNI_Memcpy((DRM_WCHAR*)sDstrHDSPath.pwszString + bdrm_get_hds_dir_lgth(), hdsFname, (bdrm_get_pr3x_hds_fname_lgth() + 1) * sizeof(DRM_WCHAR));


    if (hdsFname != NULL && bdrm_get_pr3x_hds_fname_lgth() > 0) {
        if (bdrm_get_hds_dir_lgth() > 0)
        {
            BKNI_Memcpy((DRM_WCHAR*)sDstrHDSPath.pwszString, hdsDir, bdrm_get_hds_dir_lgth() * sizeof(DRM_WCHAR));
            BKNI_Memcpy((DRM_WCHAR*)sDstrHDSPath.pwszString + bdrm_get_hds_dir_lgth(),
                        hdsFname, (bdrm_get_pr3x_hds_fname_lgth() + 1) * sizeof(DRM_WCHAR));
        }
    }

    ChkDR( Drm_Initialize(prdyCtx.pDrmAppCtx,
                          prdyCtx.pOEMContext,
                          prdyCtx.pbOpaqueBuffer,
                          prdyCtx.cbOpaqueBuffer,
                          &sDstrHDSPath) );

    printf("**** DRM SECURE CLOCK INIT\n");
    dr = Drm_SecureTime_GetValue( prdyCtx.pDrmAppCtx, &ftSystemTime, &eClockType  );
    if( (dr == DRM_E_SECURETIME_CLOCK_NOT_SET) || (dr == DRM_E_TEE_PROVISIONING_REQUIRED) )
    {
       /* setup the Playready secure clock */
       if(initSecureClock(prdyCtx.pDrmAppCtx) != 0)
       {
           BDBG_ERR(("%d Failed to initiize Secure Clock, quitting....\n",__LINE__));
           goto ErrorExit;
       }
    }
    else if (dr == DRM_E_CLK_NOT_SUPPORTED)  /* Secure Clock not supported, try the Anti-Rollback Clock */
    {
        DRMSYSTEMTIME   systemTime;
        struct timeval  tv;
        struct tm      *tm;

        BDBG_LOG(("%d Secure Clock not supported, trying the Anti-Rollback Clock...\n",__LINE__));

        gettimeofday(&tv, NULL);
        tm = gmtime(&tv.tv_sec);

        systemTime.wYear         = tm->tm_year+1900;
        systemTime.wMonth        = tm->tm_mon+1;
        systemTime.wDayOfWeek    = tm->tm_wday;
        systemTime.wDay          = tm->tm_mday;
        systemTime.wHour         = tm->tm_hour;
        systemTime.wMinute       = tm->tm_min;
        systemTime.wSecond       = tm->tm_sec;
        systemTime.wMilliseconds = tv.tv_usec/1000;

       if(Drm_AntiRollBackClock_Init(prdyCtx.pDrmAppCtx, &systemTime) != 0)
       {
           BDBG_ERR(("%d Failed to initiize Anti-Rollback Clock, quitting....\n",__LINE__));
           goto ErrorExit;
       }
    }
    else
    {
        BDBG_ERR(("%d Expect platform to support Secure Clock or Anti-Rollback Clock.  Possible certificate error.\n",__LINE__));
        goto ErrorExit;
    }

    ChkDR( Drm_Revocation_SetBuffer( prdyCtx.pDrmAppCtx,
                                     pbRevocationBuffer,
                                     REVOCATION_BUFFER_SIZE ) );
#endif // USE_OCDM

    BDBG_MSG(("@@@ Check Point #01"));
    printf("**** ACQUIRE VIDEO DECODER\n");
    if (allocResults.simpleVideoDecoder[0].id) {
        BDBG_MSG(("@@@ to acquire video decoder"));
        videoDecoder = NEXUS_SimpleVideoDecoder_Acquire(allocResults.simpleVideoDecoder[0].id);
    }
    BDBG_ASSERT(videoDecoder);

    printf("**** ACQUIRE AUDIO DECODER\n");
    if (allocResults.simpleAudioDecoder.id) {
        BDBG_MSG(("@@@ to acquire audio decoder"));
        audioDecoder = NEXUS_SimpleAudioDecoder_Acquire(allocResults.simpleAudioDecoder.id);
    }
    BDBG_ASSERT(audioDecoder);

    printf("**** ACQUIRE SURFACE CLIENT\n");
    if (allocResults.surfaceClient[0].id) {
        BDBG_MSG(("@@@ to acquire surfaceclient"));
        /* surfaceClient is the top-level graphics window in which video will fit.
        videoSurfaceClient must be "acquired" to associate the video window with surface compositor.
        Graphics do not have to be submitted to surfaceClient for video to work, but at least an
        "alpha hole" surface must be submitted to punch video through other client's graphics.
        Also, the top-level surfaceClient ID must be submitted to NxClient_ConnectSettings below. */
        surfaceClient = NEXUS_SurfaceClient_Acquire(allocResults.surfaceClient[0].id);
        videoSurfaceClient = NEXUS_SurfaceClient_AcquireVideoWindow(surfaceClient, 0);
#ifdef ANDROID
        NxClient_GetSurfaceClientComposition(allocResults.surfaceClient[0].id, &comp);
        comp.zorder = 10;   /* try to stay on top most */
        NxClient_SetSurfaceClientComposition(allocResults.surfaceClient[0].id, &comp);
#endif
    }
    printf("**** INITIALIZE CONNECT SETTINGS\n");
    NxClient_GetDefaultConnectSettings(&connectSettings);
    connectSettings.simpleVideoDecoder[0].id = allocResults.simpleVideoDecoder[0].id;
    connectSettings.simpleVideoDecoder[0].surfaceClientId = allocResults.surfaceClient[0].id;
    connectSettings.simpleAudioDecoder.id = allocResults.simpleAudioDecoder.id;
#if SAGE_ENABLE
    printf("**** ENABLE SECURE VIDEO\n");
    connectSettings.simpleVideoDecoder[0].decoderCapabilities.secureVideo = true;
#endif

#ifdef ANDROID
    /* Check the decoder capabilities for the highest resolution. */
    NEXUS_GetVideoDecoderCapabilities(&caps);
    for ( i = 0; i < (int)caps.numVideoDecoders; i++ )
    {
        NEXUS_VideoFormat_GetInfo(caps.memory[i].maxFormat, &videoInfo);
        if ( videoInfo.width > maxDecoderWidth ) {
            maxDecoderWidth = videoInfo.width;
        }
        if ( videoInfo.height > maxDecoderHeight ) {
            maxDecoderHeight = videoInfo.height;
        }
    }
    connectSettings.simpleVideoDecoder[0].decoderCapabilities.maxWidth = maxDecoderWidth;
    connectSettings.simpleVideoDecoder[0].decoderCapabilities.maxHeight = maxDecoderHeight;
#endif

    printf("**** NXCLIENT CONNECT\n");
    rc = NxClient_Connect(&connectSettings, &connectId);
    if (rc)
    {
        BDBG_ERR(("Error in NxClient_Connect"));
        goto ErrorExit;
    }

    rc = gui_init( surfaceClient );
    if (rc)
    {
        BDBG_ERR(("Error in gui_init"));
        goto ErrorExit;
    }

    printf("**** PLAYBACK PIFF\n");
    ret = playback_piff(videoDecoder,
                  audioDecoder,
                  &prdyCtx,
                  argv[1]);

ErrorExit:

    printf("**** ErrorExit / DTOR\n");
    if (videoDecoder != NULL) {
        NEXUS_SimpleVideoDecoder_Release( videoDecoder );
    }

    if ( audioDecoder != NULL) {
        NEXUS_SimpleAudioDecoder_Release( audioDecoder );
    }

    if ( surfaceClient != NULL ) {
        NEXUS_SurfaceClient_Release( surfaceClient );
    }



#ifndef USE_OCDM
    if( prdyCtx.pDrmAppCtx ) {
        Drm_Uninitialize( prdyCtx.pDrmAppCtx );
        Oem_MemFree(prdyCtx.pDrmAppCtx );
    }
    Oem_MemFree(prdyCtx.pbOpaqueBuffer);
    Oem_MemFree(pbRevocationBuffer);

    Drm_Platform_Uninitialize(prdyCtx.pOEMContext);
#endif

    NxClient_Disconnect(connectId);
    NxClient_Free(&allocResults);
    NxClient_Uninit();

    return ret;
}

static NEXUS_Error gui_init( NEXUS_SurfaceClientHandle surfaceClient )
{
    NEXUS_Graphics2DHandle gfx = NULL;
    NEXUS_SurfaceHandle surface = NULL;

    NEXUS_Graphics2DSettings gfxSettings;
    NEXUS_SurfaceCreateSettings createSettings;
    NEXUS_Graphics2DFillSettings fillSettings;
    NEXUS_Error rc= NEXUS_SUCCESS;

    if (!surfaceClient) {
        rc = NEXUS_INVALID_PARAMETER;
        goto ErrorExit;
    }

    BDBG_MSG(("@@@ gui_init surfaceclient %p", (void *)surfaceClient));
    gfx = NEXUS_Graphics2D_Open(NEXUS_ANY_ID, NULL);
    if (!gfx) {
        rc =  NEXUS_INVALID_PARAMETER;
        goto ErrorExit;
    }

    NEXUS_Graphics2D_GetSettings(gfx, &gfxSettings);
    rc = NEXUS_Graphics2D_SetSettings(gfx, &gfxSettings);
    if(rc != NEXUS_SUCCESS) {
        goto ErrorExit;
    }

    NEXUS_Surface_GetDefaultCreateSettings(&createSettings);
    createSettings.pixelFormat = NEXUS_PixelFormat_eA8_R8_G8_B8;
    createSettings.width = 720;
    createSettings.height = 480;
    surface = NEXUS_Surface_Create(&createSettings);
    if(!surface) {
        rc =  NEXUS_INVALID_PARAMETER;
        goto ErrorExit;
    }

    NEXUS_Graphics2D_GetDefaultFillSettings(&fillSettings);
    fillSettings.surface = surface;
    fillSettings.color = 0;
    rc = NEXUS_Graphics2D_Fill(gfx, &fillSettings);
    if(rc != NEXUS_SUCCESS) {
        goto ErrorExit;
    }

    rc = NEXUS_Graphics2D_Checkpoint(gfx, NULL); /* require to execute queue */
    if(rc != NEXUS_SUCCESS
        && rc != NEXUS_GRAPHICS2D_QUEUED) {
        goto ErrorExit;
    }

    rc = NEXUS_SurfaceClient_SetSurface(surfaceClient, surface);
    if(rc != NEXUS_SUCCESS) {
        goto ErrorExit;
    }

ErrorExit:
    if(surface) NEXUS_Surface_Destroy(surface);
    if(gfx) NEXUS_Graphics2D_Close(gfx);

    return rc;
}


#ifdef ANDROID
static bool setupRuntimeHeaps( bool secureDecoder, bool secureHeap )
{
    unsigned i;
    NEXUS_Error errCode;
    NEXUS_PlatformConfiguration platformConfig;
    NEXUS_PlatformSettings platformSettings;
    NEXUS_MemoryStatus memoryStatus;

    NEXUS_Platform_GetConfiguration(&platformConfig);
    for (i = 0; i < NEXUS_MAX_HEAPS ; i++)
    {
       if (platformConfig.heap[i] != NULL)
       {
          errCode = NEXUS_Heap_GetStatus(platformConfig.heap[i], &memoryStatus);
          if (!errCode && (memoryStatus.heapType & NEXUS_HEAP_TYPE_PICTURE_BUFFERS))
          {
             NEXUS_HeapRuntimeSettings settings;
             bool origin, wanted;
             NEXUS_Platform_GetHeapRuntimeSettings(platformConfig.heap[i], &settings);
             origin = settings.secure;
             wanted = secureHeap ? true : false;
             if (origin != wanted)
             {
                settings.secure = wanted;
                errCode = NEXUS_Platform_SetHeapRuntimeSettings(platformConfig.heap[i], &settings);
                if (errCode)
                {
                   BDBG_ERR(("NEXUS_Platform_SetHeapRuntimeSettings(%i:%p, %s) on decoder %s -> failed: %d",
                            i, platformConfig.heap[i], settings.secure?"secure":"open",
                            secureDecoder?"secure":"open", errCode));
                   /* Continue anyways, something may still work... */
                   if (origin && !wanted)
                   {
                      BDBG_ERR(("origin %d, wanted %d combination unexpected, continue anyways", origin, wanted));
                      return false;
                   }
                }
                else
                {
                   BDBG_LOG(("NEXUS_Platform_SetHeapRuntimeSettings(%i:%p, %s) on decoder %s -> success", i, platformConfig.heap[i], settings.secure?"secure":"open", secureDecoder?"secure":"open"));
                }
             }
          }
       }
    }
    return true;
}
#endif

