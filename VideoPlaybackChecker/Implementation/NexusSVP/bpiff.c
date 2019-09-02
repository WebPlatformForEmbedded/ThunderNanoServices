/******************************************************************************
* Copyright (C) 2017 Broadcom. The term "Broadcom" refers to Broadcom Limited and/or its subsidiaries.
*
* This program is the proprietary software of Broadcom and/or its licensors,
* and may only be used, duplicated, modified or distributed pursuant to the terms and
* conditions of a separate, written license agreement executed between you and Broadcom
* (an "Authorized License").  Except as set forth in an Authorized License, Broadcom grants
* no license (express or implied), right to use, or waiver of any kind with respect to the
* Software, and Broadcom expressly reserves all rights in and to the Software and all
* intellectual property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU
* HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY
* NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
*
* Except as expressly set forth in the Authorized License,
*
* 1.     This program, including its structure, sequence and organization, constitutes the valuable trade
* secrets of Broadcom, and you shall use all reasonable efforts to protect the confidentiality thereof,
* and to use this information only in connection with your use of Broadcom integrated circuit products.
*
* 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
* AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
* WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
* THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND ALL IMPLIED WARRANTIES
* OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,
* LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION
* OR CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF
* USE OR PERFORMANCE OF THE SOFTWARE.
*
* 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR ITS
* LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL, INDIRECT, OR
* EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY RELATING TO YOUR
* USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF
* THE POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT
* ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE
* LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF
* ANY LIMITED REMEDY.
******************************************************************************/

#include "bpiff.h"
#include "bmedia_util.h"
#include "bmp4_util.h"
#include "nexus_memory.h"
#include "bkni.h"
#include "biobits.h"

#define BMP4_VISUAL_ENTRY_SIZE   (78)  /* Size of a Visual Sample Entry in bytes */
#define BMP4_AUDIO_ENTRY_SIZE    (28)  /* Size of an Audio Sample Entry in bytes */

#define BMP4_PROTECTIONSCHEMEINFO BMP4_TYPE('s','i','n','f')
#define BMP4_ORIGINALFMT          BMP4_TYPE('f','r','m','a')
#define BMP4_IPMPINFO             BMP4_TYPE('i','m','i','f')
#define BMP4_SCHEMETYPE           BMP4_TYPE('s','c','h','m')
#define BMP4_SCHEMEINFO           BMP4_TYPE('s','c','h','i')
#define BMP4_PIFF_SCHEMETYPE      BMP4_TYPE('p','i','f','f')
#define BMP4_CENC_SCHEMETYPE      BMP4_TYPE('c','e','n','c')
#define BMP4_CENC_TE_BOX          BMP4_TYPE('t','e','n','c')

#define BMP4_DASH_PSSH            BMP4_TYPE('p','s','s','h')
#define BMP4_PROPRITARY_BMP4      BMP4_TYPE('b','m','p','4')

#define BMP4_CENC_AVCC            BMP4_TYPE('a','v','c','C')
#define BMP4_CENC_ESDS            BMP4_TYPE('e','s','d','s')
#define BMP4_CENC_WFEX            BMP4_TYPE('w','f','e','x')
#define BMP4_CENC_DVC1            BMP4_TYPE('d','v','c','1')

#define AAC_ESDS_ES_HDR_OFFSET    35

/*PLAYREADY */
static const bmedia_guid bmedia_protection_system_identifier_guid =
{{0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95}};

static bmp4_box_extended pssh_extended_type =
{{0xd0, 0x8a, 0x4f, 0x18, 0x10, 0xf3, 0x4a, 0x82, 0xb6, 0xc8, 0x32, 0xd8, 0xab, 0xa1, 0x83, 0xd3}};

static bmp4_box_extended track_enc_extended_type =
{{0x89, 0x74, 0xdb, 0xce, 0x7b, 0xe7, 0x4c, 0x51, 0x84, 0xf9, 0x71, 0x48, 0xf9, 0x88, 0x25, 0x54}};


#define CONVERT_ALG_ID_TO_BPIFF_ENCR_STATE(_alg_id, _state) do { \
    if(_alg_id == 0) _state = bpiff_encryptionType_eNone;            \
    else if(_alg_id == 1) _state = bpiff_encryptionType_eAesCtr;     \
    else _state = bpiff_encryptionType_eAesCbc;  }while(0)

/* PIFF Protection System Specific Header Box */
typedef struct bpiff_pssh_header {
    bmp4_box_extended extended;
    bmp4_fullbox fullbox;
    uint8_t  systemId[16];
} bpiff_pssh_header;

typedef struct bpiff_trackInfo {
    bpiff_protectionSchemeInfo scheme; /* Will be set to NULL of no protection scheme box is found for the track */
    bool scheme_box_valid;
    bool piff_1_3;
} bpiff_trackInfo;

BDBG_MODULE(bpiff);

void bpiff_GetDefaultMp4Header(bpiff_mp4_headers *pMp4)
{
     if (pMp4) {
        BKNI_Memset(pMp4, 0, sizeof(bpiff_mp4_headers));
     }
}

void bpiff_FreeMp4Header(bpiff_mp4_headers *pMp4)
{
    if(pMp4->pPsshData != NULL) NEXUS_Memory_Free((void*) pMp4->pPsshData);
}

void bpiff_InitMp4FragHeader(bpiff_mp4_frag_headers *pMp4Frag)
{
     if (pMp4Frag) {
        BKNI_Memset(pMp4Frag, 0, sizeof(bpiff_mp4_frag_headers));
        bmp4_init_track_fragment_run_state(&pMp4Frag->state);
     }
}

static
int bpiff_parse_sinf(batom_cursor *cursor, bmp4_box *pBox, bpiff_trackInfo *pTrack)
{
    int     rc = 0;
    bmp4_box     box;
    bmp4_box     te_box;
    size_t       box_hdr_size;
    uint32_t     i;
    bpiff_protectionSchemeInfo  *pScheme = NULL;

    bmp4_box_extended extended;
    bmp4_fullbox     fullbox;

    bool found_piff= false;
    bool found_fmt= false;
    bool found_extended= false;
    bool found_cenc = false;
    bool found_tenc = false;
    uint32_t alg_id;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_PROTECTIONSCHEMEINFO);

    pScheme = &pTrack->scheme;

    for(i = 0; i < pBox->size; i += (box_hdr_size + box.size))
    {
        box_hdr_size = bmp4_parse_box(cursor, &box);

        if(box_hdr_size == 0) {
            break;
        }

        switch(box.type){
            case BMP4_ORIGINALFMT:
                pScheme->originalFormat.codingName =  batom_cursor_uint32_be(cursor);
                found_fmt= true;
                break;
            case BMP4_SCHEMETYPE:

                if(!bmp4_parse_fullbox(cursor, &fullbox)){
                    rc = -1; goto ErrorExit;
                }

                pScheme->schemeType.version = fullbox.version;
                pScheme->schemeType.flags = fullbox.flags;

                pScheme->schemeType.schemeType = batom_cursor_uint32_be(cursor);
                if (pScheme->schemeType.schemeType == BMP4_CENC_SCHEMETYPE) {
                    found_cenc = true;
                    BDBG_MSG(("found 'cenc'"));
                }
                else if (pScheme->schemeType.schemeType == BMP4_PIFF_SCHEMETYPE) {
                    found_piff = true;
                }
                else {
                    batom_cursor_skip(cursor, box.size - box_hdr_size - box_hdr_size);
                    continue;
                }
                pScheme->schemeType.schemeVersion = batom_cursor_uint32_be(cursor);

                /* Skip over scheme uri, if present */
                if(pScheme->schemeType.flags & 0x000001)
                    batom_cursor_skip(cursor, 1);

                break;
            case BMP4_SCHEMEINFO:
                box_hdr_size = bmp4_parse_box(cursor, &te_box);

                if(box_hdr_size == 0) {
                    break;
                }

                if (te_box.type == BMP4_CENC_TE_BOX) {
                    found_tenc = true;
                    BDBG_MSG(("found 'tenc'"));
                    if (found_piff) {
                        BDBG_WRN(("expected 'uuid' box but 'tenc' is found"));
                    }
                }
                else if (te_box.type == BMP4_EXTENDED) {
                    found_extended = true;
                    if (found_cenc) {
                        BDBG_WRN(("expected 'tenc' box but 'uuid' is found"));
                    }
                    else {
                        BDBG_MSG(("found 'uuid'"));
                    }
                    if (!bmp4_parse_box_extended(cursor, &extended)) {
                        rc = -1; goto ErrorExit;
                    }
                    /* Make sure we found a TE box. */
                    if (BKNI_Memcmp(extended.usertype, track_enc_extended_type.usertype, 16) != 0) {
                        goto ErrorExit;
                    }
                }
                else {
                    /* Streams can have more than one schi box which contains other things than uuid or tenc. Just skip over it */
                    batom_cursor_skip(cursor, te_box.size - box_hdr_size);
                    continue;
                }

                if(!bmp4_parse_fullbox(cursor, &fullbox)){
                    rc = -1; goto ErrorExit;
                }
                pScheme->trackEncryption.version = fullbox.version;
                pScheme->trackEncryption.flags = fullbox.flags;

                alg_id = batom_cursor_uint24_be(cursor);
                CONVERT_ALG_ID_TO_BPIFF_ENCR_STATE(alg_id, pScheme->trackEncryption.info.algorithm);

                pScheme->trackEncryption.info.ivSize = batom_cursor_byte(cursor);
                batom_cursor_copy(cursor,pScheme->trackEncryption.info.keyId, 16);

                break;
            case BMP4_IPMPINFO:
                /* This box doesn't contain any meaningfull Playready info, Ignore it*/
            default :
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }
    }

ErrorExit:
    if (found_fmt == true && found_piff == true && found_extended == true) {
        pTrack->scheme_box_valid = true;
    }

    if (found_fmt == true && found_cenc == true && found_tenc == true) {
        pTrack->scheme_box_valid = true;
        pTrack->piff_1_3 = true;
    }

    return rc;
}

static
int bpiff_parse_stsd(batom_cursor *cursor, bmp4_box *pBox, bpiff_trackInfo *pTrack)
{
    int     rc = -1;
    bmp4_box     box;
    size_t       box_hdr_size;
    size_t       entry_hdr_size;
    uint32_t     i, j;
    bmp4_box entry_box;
    bmp4_fullbox fullbox;

    uint32_t entry_count = 0;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_SAMPLEDESCRIPTION);

    if(!bmp4_parse_fullbox(cursor, &fullbox)) {
        return -1;
    }

    entry_count = batom_cursor_uint32_be(cursor);

    for(i = 0; i < entry_count; i++){
        entry_hdr_size = bmp4_parse_box(cursor, &entry_box);
        if(entry_hdr_size == 0) {
            break;
        }

        if((entry_box.type==BMP4_SAMPLE_ENCRYPTED_VIDEO) ||
                (entry_box.type==BMP4_SAMPLE_ENCRYPTED_AUDIO) )
        {
            uint32_t skip_bytes = (entry_box.type == BMP4_SAMPLE_ENCRYPTED_VIDEO ?
                BMP4_VISUAL_ENTRY_SIZE:BMP4_AUDIO_ENTRY_SIZE);

            pTrack->scheme.trackType = entry_box.type;
            batom_cursor_skip(cursor, skip_bytes);

            for(j = skip_bytes + entry_hdr_size; j < entry_box.size; j += box.size)
            {
                box_hdr_size = bmp4_parse_box(cursor, &box);
                if(box_hdr_size == 0) {
                    break;
                }

                if(box.type == BMP4_PROTECTIONSCHEMEINFO) {
                    rc = bpiff_parse_sinf(cursor, &box, pTrack);
                    if(rc != 0) {
                        goto ErrorExit;
                    }
                    else if (pTrack->scheme_box_valid == true) {
                        /* No need to dig further once a valid TE box has been parsed */
                        goto ErrorExit;
                    }
                } else if (box.type == BMP4_CENC_DVC1) {
                    BDBG_MSG(("%s - Got the DVC1 box, read the vc1_config data\n", BSTD_FUNCTION));
                    batom_cursor_copy(cursor, pTrack->scheme.decConfig.data, box.size-box_hdr_size);
                    pTrack->scheme.decConfig.size = box.size-box_hdr_size;
                } else if(box.type == BMP4_CENC_AVCC) {
                    BDBG_MSG(("%s - Got the AvcC box, read the avc_config data\n", BSTD_FUNCTION));
                    batom_cursor_copy(cursor, pTrack->scheme.decConfig.data, box.size-box_hdr_size);
                    pTrack->scheme.decConfig.size = box.size-box_hdr_size;
                } else if(box.type == BMP4_CENC_WFEX) {
                    BDBG_MSG(("%s - Got the wmap box, read the wmapro_config data\n", BSTD_FUNCTION));
                    batom_cursor_copy(cursor, pTrack->scheme.decConfig.data, box.size-box_hdr_size);
                    pTrack->scheme.decConfig.size = box.size-box_hdr_size;
                } else if(box.type == BMP4_CENC_ESDS) {
                    bmedia_info_aac info_aac;
                    batom_cursor aac_cursor;

                    BATOM_CLONE(&aac_cursor, cursor);
                    batom_cursor_skip(&aac_cursor, AAC_ESDS_ES_HDR_OFFSET);

                    BDBG_MSG(("%s - Got the esds box, read the aac_config data\n", BSTD_FUNCTION));

                    bmedia_info_probe_aac_info(&aac_cursor, &info_aac);
                    BKNI_Memcpy(pTrack->scheme.decConfig.data, &info_aac, sizeof(bmedia_info_aac));
                    pTrack->scheme.decConfig.size = sizeof(bmedia_info_aac);
                    batom_cursor_skip(cursor, box.size - box_hdr_size);
                } else {
                    batom_cursor_skip(cursor, box.size - box_hdr_size);
                }
            }
        } else {
            batom_cursor_skip(cursor, entry_box.size - entry_hdr_size);
        }
    }

ErrorExit:
    return rc;
}


    static
int bpiff_parse_stbl(batom_cursor *cursor, bmp4_box *pBox, bpiff_trackInfo *pTrack)
{
    int     rc = 0;
    bmp4_box     box;
    size_t       box_hdr_size;
    uint32_t     i;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_SAMPLETABLE);

    for(i = 0; i < pBox->size; i += (box_hdr_size + box.size))
    {
        box_hdr_size = bmp4_parse_box(cursor, &box);

        if(box_hdr_size == 0) {
            break;
        }

        switch(box.type){
            case BMP4_SAMPLEDESCRIPTION:
                rc = bpiff_parse_stsd(cursor, &box, pTrack);
                if(rc != 0) goto ErrorExit;
                break;
            default :
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }
    }

ErrorExit:
    return rc;
}

static
int bpiff_parse_minf(batom_cursor *cursor, bmp4_box *pBox, bpiff_trackInfo *pTrack)
{

    int     rc = 0;
    bmp4_box     box;
    size_t       box_hdr_size;
    uint32_t     i;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_MEDIAINFORMATION);

    for(i = 0; i < pBox->size; i += (box_hdr_size + box.size))
    {
        box_hdr_size = bmp4_parse_box(cursor, &box);

        if(box_hdr_size == 0) {
            break;
        }

        switch(box.type){
            case BMP4_SAMPLETABLE:
                rc = bpiff_parse_stbl(cursor, &box, pTrack);
                if(rc != 0) goto ErrorExit;
                break;
            default :
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }
    }

ErrorExit:
    return rc;
}

static
int bpiff_parse_mdia(batom_cursor *cursor, bmp4_box *pBox, bpiff_trackInfo *pTrack)
{
    int     rc = 0;
    bmp4_box     box;
    size_t       box_hdr_size;
    uint32_t     i;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_MEDIA);

    for(i = 0; i < pBox->size; i += (box_hdr_size + box.size))
    {
        box_hdr_size = bmp4_parse_box(cursor, &box);

        if(box_hdr_size == 0) {
            break;
        }

        switch(box.type){
            case BMP4_MEDIAINFORMATION:
                rc = bpiff_parse_minf(cursor, &box, pTrack);
                if(rc != 0) goto ErrorExit;
                break;
            default :
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }
    }

ErrorExit:
    return rc;
}

static
int bpiff_parse_trak(bpiff_mp4_headers *header, batom_t atom, batom_cursor *cursor, bmp4_box *pBox)
{
    int     rc = 0;
    bmp4_box     box;
    size_t       box_hdr_size;
    uint32_t     i;
    bpiff_trackInfo  track;
    bmp4_trackheaderbox  track_header;
    bpiff_protectionSchemeInfo *pScheme;
    batom_t tkhd = NULL;
    batom_cursor start;

    BDBG_ASSERT(atom != NULL);
    BDBG_ASSERT(pBox->type == BMP4_TRACK);

    BKNI_Memset(&track, 0, sizeof(bpiff_trackInfo));

    for(i = 0; i < pBox->size; i += (box_hdr_size + box.size))
    {
        box_hdr_size = bmp4_parse_box(cursor, &box);
        if(box_hdr_size == 0) {
            break;
        }

        switch(box.type){
            case BMP4_TRACKHEADER:
                /* Get an atom on the track header. */
                BATOM_CLONE(&start, cursor);
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                tkhd = batom_extract(atom, &start, cursor, NULL, NULL);

                if(!bmp4_parse_trackheader(tkhd, &track_header)){
                    rc = -1; goto ErrorExit;
                }
                track.scheme.trackId = track_header.track_ID;
                break;
            case BMP4_MEDIA:
                rc = bpiff_parse_mdia(cursor, &box, &track);
                if(rc != 0) {
                    goto ErrorExit;
                }
                break;
            default :
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }
    }

    if(track.scheme_box_valid){
        pScheme = &header->scheme[track.scheme.trackId];
        BKNI_Memcpy(pScheme, &track.scheme, sizeof(bpiff_protectionSchemeInfo));
        header->nbOfSchemes++;
    }

    if (track.piff_1_3) {
        header->piff_1_3 = true;
    }

ErrorExit:
    if (tkhd) {
        batom_release(tkhd);
    }
    if(rc != 0){
        /*if(pNode != NULL) BKNI_Free(pNode);*/
    }
    return rc;
}

static
int bpiff_parse_piff_pssh(bpiff_mp4_headers *header, batom_cursor *cursor, bmp4_box *pBox)
{
    int     rc = -1;
    NEXUS_Error errCode;

    bpiff_pssh_header psshHeader; /* Might have more than one in the stream */
    NEXUS_MemoryAllocationSettings allocSettings;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_EXTENDED);

    if(bmp4_parse_box_extended(cursor, &psshHeader.extended)){
        if(bmp4_parse_fullbox(cursor, &psshHeader.fullbox)){
            if(BKNI_Memcmp(psshHeader.extended.usertype, pssh_extended_type.usertype, 16) == 0){
                batom_cursor_copy(cursor, psshHeader.systemId, 16);
                /* Verify that the PSSH object found is really one describing the Playready content protection system */
                if(BKNI_Memcmp(psshHeader.systemId, bmedia_protection_system_identifier_guid.guid, 16) == 0){
                    BKNI_Memcpy(header->psshSystemId.systemId.data, &psshHeader.systemId, 16);
                    header->psshDataLength = batom_cursor_uint32_be(cursor);
                    NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);

                    errCode = NEXUS_Memory_Allocate(header->psshDataLength, &allocSettings, (void **)(&header->pPsshData));
                    if ( errCode )
                        return rc;

                    batom_cursor_copy(cursor, header->pPsshData, header->psshDataLength);
                    rc = 0;
                }
            }
            else {
                /* Found another PSSH box. Might be a test box*/
                batom_cursor_skip(cursor, pBox->size - 8 - 4 - 16);
                rc = 0;
            }
        }
    }

    return rc;
}


static
int bpiff_parse_dash_pssh(bpiff_mp4_headers *header, batom_cursor *cursor, bmp4_box *pBox)
{
    int     rc = -1;
    NEXUS_Error errCode;

    bpiff_pssh_header psshHeader; /* Might have more than one in the stream */
    NEXUS_MemoryAllocationSettings allocSettings;

    BDBG_ASSERT(cursor != NULL);
    BDBG_ASSERT(pBox->type == BMP4_DASH_PSSH);

    if(bmp4_parse_fullbox(cursor, &psshHeader.fullbox)){
        batom_cursor_copy(cursor, psshHeader.systemId, 16);

        /* Verify that the PSSH object found is really one describing the Playready content protection system */
        if(BKNI_Memcmp(psshHeader.systemId, bmedia_protection_system_identifier_guid.guid, 16) == 0){
            BKNI_Memcpy(header->psshSystemId.systemId.data, &psshHeader.systemId, 16);

            header->psshDataLength = batom_cursor_uint32_be(cursor);

            NEXUS_Memory_GetDefaultAllocationSettings(&allocSettings);
            errCode = NEXUS_Memory_Allocate(header->psshDataLength, &allocSettings, (void **)(&header->pPsshData));
            if ( errCode )
                return rc;

            batom_cursor_copy(cursor, header->pPsshData, header->psshDataLength);
            rc = 0;
        }
        else {
            /* Found another PSSH box. Might be a test box*/
            batom_cursor_skip(cursor, pBox->size - 8 - 4 - 16);
            rc = 0;
        }
    }

    return rc;
}

static
int bpiff_parse_sample_enc_extended_box(bpiff_mp4_frag_headers *frag_header, batom_cursor *cursor)
{
    uint32_t     i,j;
    bpiff_drm_mp4_box_se_sample *pSample;
    bpiff_drm_mp4_box_se_entry *pEntry;
    bmp4_fullbox fullbox;

    if (bmp4_parse_fullbox(cursor, &fullbox)) {
        frag_header->samples_enc.sample_count = batom_cursor_uint32_be(cursor);

        if (frag_header->samples_enc.sample_count != 0) {
            if (frag_header->samples_enc.sample_count > BPIFF_SAMPLES_POOL_SIZE) {
                BDBG_ERR(("Increase pool of %d to handle number of samples: %d\n",
                    BPIFF_SAMPLES_POOL_SIZE, frag_header->samples_enc.sample_count));
                return -1;
            }

        frag_header->samples_enc.flags = fullbox.flags;
            pSample = frag_header->samples_enc.samples;
            BKNI_Memset(pSample, 0, sizeof(bpiff_drm_mp4_box_se_sample));

            for(i = 0; i < frag_header->samples_enc.sample_count; i++){
                uint8_t *pIv;

                batom_cursor_copy(cursor, &pSample->iv[15], 1);
                batom_cursor_copy(cursor, &pSample->iv[14], 1);
                batom_cursor_copy(cursor, &pSample->iv[13], 1);
                batom_cursor_copy(cursor, &pSample->iv[12], 1);
                batom_cursor_copy(cursor, &pSample->iv[11], 1);
                batom_cursor_copy(cursor, &pSample->iv[10], 1);
                batom_cursor_copy(cursor, &pSample->iv[9], 1);
                batom_cursor_copy(cursor, &pSample->iv[8], 1);

                BKNI_Memset(&pSample->iv[0], 0, 8);

                pIv = &frag_header->samples_enc.samples[i].iv[0];

                if (frag_header->samples_enc.flags & 0x000002) {
                    pSample->nbOfEntries = batom_cursor_uint16_be(cursor);

                    if (pSample->nbOfEntries != 0) {
                        if (pSample->nbOfEntries  > BPIFF_MAX_ENTRIES_PER_SAMPLE) {
                            BDBG_ERR(("%s: Default nb of entry too small, increase MAX_ENTRIES_PER_SAMPLE\n", __func__));
                            return -1;
                        }
                        pEntry = pSample->entries;

                        for(j = 0; j <  pSample->nbOfEntries; j++) {
                            pEntry->bytesOfClearData = batom_cursor_uint16_be(cursor);
                            pEntry->bytesOfEncData = batom_cursor_uint32_be(cursor);
                            pEntry++;
                        }
                    }
                }
                pSample++;
        }
    }
    }
    return 0;
}

static
int bpiff_parse_traf(bpiff_mp4_headers *header, bpiff_mp4_frag_headers *frag_header,
        batom_cursor *cursor, bmp4_box traf)
{
    uint32_t i, j;
    bmp4_box box;
    size_t box_hdr_size;
    bmp4_track_fragment_header bmp4_frag_hdr;
    bmp4_track_fragment_run_header bmp4_run_hdr;
    bmp4_box_extended senc_box;
    bmp4_trackextendsbox track_extends;
    int rc = -1;
    bool skip_frag = false;

    for (i = 0; i < traf.size; i += (box_hdr_size + box.size)) {
        box_hdr_size = bmp4_parse_box(cursor, &box);
        if (box_hdr_size == 0)
            break;

        switch (box.type) {
            case BMP4_TRACK_FRAGMENT_HEADER:
            {
                uint32_t trackId;
                uint32_t trackType;

                bmp4_parse_track_fragment_header(cursor, &bmp4_frag_hdr);
                trackId = bmp4_frag_hdr.track_ID;
                if (trackId < BPIFF_MAX_NB_OF_TRACKS)
                    trackType = header->scheme[trackId].trackType;
                else {
                    BDBG_ERR(("%s: Invalid fragment track ID in movie information header \n",
                        __func__));
                    skip_frag = true;
                }

                if (trackType != BMP4_SAMPLE_ENCRYPTED_VIDEO &&
                    trackType != BMP4_SAMPLE_ENCRYPTED_AUDIO) {
                    BDBG_WRN(("%s: Detected unexpected track type in fragment 0x%x, skip over.\n",
                        __func__, trackType));
                    skip_frag = true;
                } else {
                    frag_header->trackId = trackId;
                    frag_header->trackType = trackType;
                }
                break;
            }
            case BMP4_TRACK_FRAGMENT_RUN:
            {
                bmp4_parse_track_fragment_run_header(cursor, &bmp4_run_hdr);

                if(bmp4_run_hdr.sample_count > BPIFF_MAX_SAMPLES) {
                    BDBG_ERR(("%s: Sample count of %d in fragment is too large for pool of %d samples\n",
                    __func__, bmp4_run_hdr.sample_count, BPIFF_MAX_SAMPLES));
                    goto traf_error_exit;
                }

                frag_header->run_sample_count = bmp4_run_hdr.sample_count;
                for (j = 0; j < bmp4_run_hdr.sample_count; j++) {
                    bmp4_parse_track_fragment_run_sample(cursor, &bmp4_frag_hdr,
                                    &bmp4_run_hdr, &track_extends,
                                    &frag_header->state, &frag_header->sample_info[j]);

                }
                break;
            }
            case BMP4_EXTENDED:
            {
                bmp4_parse_box_extended(cursor, &senc_box);
                rc = bpiff_parse_sample_enc_extended_box(frag_header, cursor);
                break;
            }
            default:
                /* Not the box we are looking for. Skip over it.*/
                batom_cursor_skip(cursor, box.size - box_hdr_size);
                break;
        }

        if (skip_frag) {
            BDBG_WRN(("This fragment is not a A/V track, skip to next fragment\n"));
            rc = -1;
            break;
        }
    }

traf_error_exit:
    return rc;
}

/*
look for trak box
    in the trak box, look for mdia box
        in the mdia box, look for the minf box
            in the minf box, look for the stbl box
                in the stbl box, look for the stsd box.
    in the trak box, look for tkhd box. It contains the track id
*/
int bpiff_parse_moov(bpiff_mp4_headers *header, batom_t atom)
{
    int           rc = 0;
    batom_cursor  cursor;
    bmp4_box      box;
    bmp4_box      moov;
    size_t        box_hdr_size;
    uint32_t      i;

    if(atom == NULL)
        return -1;

    batom_cursor_from_atom(&cursor, atom);

    if((box_hdr_size = bmp4_parse_box(&cursor, &moov))){

        if(moov.type == BMP4_MOVIE)
        {

            for(i = box_hdr_size; i < moov.size; i += box.size){

                box_hdr_size = bmp4_parse_box(&cursor, &box);
                if(box_hdr_size==0) {
                    break;
                }

                switch(box.type){
                    case BMP4_EXTENDED:
                        rc = bpiff_parse_piff_pssh(header, &cursor, &box);
                        if(rc != 0) {
                            goto ErrorExit;
                        }
                        break;
                    case BMP4_DASH_PSSH:  /* compatible with PIFF 1.3 */
                        rc = bpiff_parse_dash_pssh(header, &cursor, &box);
                        if(rc != 0) {
                            goto ErrorExit;
                        }
                        break;
                    case BMP4_TRACK:
                        rc = bpiff_parse_trak(header, atom, &cursor, &box);
                        if(rc != 0){
                            goto ErrorExit;
                        }
                        break;
                    default :
                        /* Not the box we are looking for. Skip over it.*/
                        batom_cursor_skip(&cursor, box.size - box_hdr_size);
                        break;
                }
            }
        }
        else {
            /* Note a MOOV box */
            rc = -1;
        }
    }
    else {
        /* Not a box */
        rc = -1;
    }

ErrorExit:
    return rc;
}

int bpiff_parse_moof(bpiff_mp4_headers *header, bpiff_mp4_frag_headers *frag_header, batom_t atom)
{
    batom_cursor cursor;
    bmp4_box box;
    bmp4_box moof;
    size_t box_hdr_size;
    uint32_t i;
    int rc = 0;

    if (atom == NULL)
        return -1;

    batom_cursor_from_atom(&cursor, atom);

    if (bmp4_parse_box(&cursor, &moof)) {
        if (moof.type == BMP4_MOVIE_FRAGMENT) {
            for(i = 0; i < moof.size; i += (box_hdr_size + box.size)) {
                box_hdr_size = bmp4_parse_box(&cursor, &box);
                if (box_hdr_size == 0)
                    break;

                if (box.type == BMP4_TRACK_FRAGMENT)
                    bpiff_parse_traf(header, frag_header, &cursor, box);
                else
                    batom_cursor_skip(&cursor, box.size - box_hdr_size);
            }
        } else {
            /* Not a MOOF box */
            rc = -1;
        }
    } else {
        /* Not a box */
        rc = -1;
    }
    return rc;
}
