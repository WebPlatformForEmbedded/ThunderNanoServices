/******************************************************************************
 *  Copyright (C) 2016 Broadcom. The term "Broadcom" refers to Broadcom Limited and/or its subsidiaries.
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

/* Example app: PIFF Parser */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "piff_parser.h"
#include "bfile_io.h"
#include "bioatom.h"
#include "bpiff.h"
#include "bstd.h"
#include "bkni.h"
#include "bkni_multi.h"
#include "balloc.h"
#include "bmp4_util.h"
#include "nexus_memory.h"

#define PIFF_BOX_HEADER_SIZE            8 /* 4 bytes size, 4 bytes header string */
#define PIFF_PARSER_FACTORY_ALLOC_SIZE  1024
#define PIFF_PAYLOAD_BUF_SIZE           (1024 * 1024 * 2) /* 2MB */

struct piff_parser_context {
    bfile_io_read_t fd;
    batom_factory_t factory;
    bpiff_mp4_headers piff_mp4;
    bpiff_mp4_frag_headers piff_mp4_frag;
    uint8_t *piff_payload;
};

static bool piff_parser_seek_box(piff_parser_handle_t handle,
            uint8_t         *pBuf,
            uint32_t         box_type,
            batom_t         *box,
            uint32_t        *box_size)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    off_t first, last;
    uint32_t curr_box_size;
    uint32_t curr_box_type = 0;
    uint32_t size_to_read;
    bool found = false;
    batom_cursor cursor;
    uint32_t size = 0;
    uint32_t payload_size = 0;
    int rc;

    rc = cntxt->fd->bounds(cntxt->fd, &first, &last);
    if (rc) {
        printf("%s: Size unavailable at handle %p\n", __func__, handle);
        goto seek_box_error;
    }

    if (last < PIFF_BOX_HEADER_SIZE) {
        printf("%s: Size too small to read box header at handle %p\n", __func__, handle);
        *box_size = 0;
        goto seek_box_error;
    }

    if (*box_size < PIFF_BOX_HEADER_SIZE ) {
        printf("%s: pBuf size too small to obtain box header at handle %p\n", __func__, handle);
    }

    while (curr_box_type != box_type) {

        /* Reset the payload size */
        payload_size = 0;

        size_to_read = PIFF_BOX_HEADER_SIZE; /* Read box header */
        size = cntxt->fd->read(cntxt->fd, pBuf, size_to_read);
        payload_size += size;
        if(size != size_to_read) {
            break;
        }


        (*box) = batom_from_range(cntxt->factory, pBuf, size_to_read, NULL, NULL);
        batom_cursor_from_atom(&cursor, (*box));

        curr_box_size = batom_cursor_uint32_be(&cursor);
        curr_box_type = batom_cursor_uint32_be(&cursor);
        *box_size     = curr_box_size;
        batom_cursor_skip(&cursor, curr_box_size - PIFF_BOX_HEADER_SIZE);

        if(curr_box_type != box_type)
            cntxt->fd->seek(cntxt->fd, curr_box_size - PIFF_BOX_HEADER_SIZE, SEEK_CUR);
        else {
            /* Found the correct box type */
            if (*box_size < curr_box_size) {
                printf("%s: Buffer too small to fit entire box\n", __func__);
                goto seek_box_error;
            }

            size_to_read = curr_box_size - PIFF_BOX_HEADER_SIZE;
            size = cntxt->fd->read(cntxt->fd, (pBuf + PIFF_BOX_HEADER_SIZE), size_to_read);
            payload_size += size;
            if(size != size_to_read) {
                printf("%s Box data read failed, expected %d bytes but read %d bytes\n", __func__, size_to_read, size);
                break;
            }


            (*box) = batom_from_range(cntxt->factory, pBuf, curr_box_size, NULL, NULL);
            found = true;

        }

        last -= curr_box_size;
        if(last == 0){
            /* EOF has been reached */
            break;
        }
    }

    *box_size = payload_size;

seek_box_error:
    return found;
}

piff_parser_handle_t piff_parser_create(bfile_io_read_t fd)
{
    struct piff_parser_context *cntxt;

    if (!fd)
        return NULL;

    cntxt = (struct piff_parser_context *)BKNI_Malloc(sizeof(struct piff_parser_context));
    cntxt->fd = fd;
    cntxt->factory = batom_factory_create(bkni_alloc, PIFF_PARSER_FACTORY_ALLOC_SIZE);
    bpiff_GetDefaultMp4Header(&cntxt->piff_mp4);
    bpiff_InitMp4FragHeader(&cntxt->piff_mp4_frag);

    if( NEXUS_Memory_Allocate(PIFF_PAYLOAD_BUF_SIZE, NULL, (void **)&cntxt->piff_payload) !=  NEXUS_SUCCESS) {
        printf("%s: NEXUS_Memory_Allocate failed\n", __func__);
        goto create_cleanup;
    }

    return cntxt;

create_cleanup:
    piff_parser_destroy(cntxt);
    return NULL;
}

void piff_parser_destroy(piff_parser_handle_t handle)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;

    if (cntxt) {
        if (cntxt->piff_payload)
            NEXUS_Memory_Free(cntxt->piff_payload);

        bpiff_FreeMp4Header(&cntxt->piff_mp4);
        batom_factory_destroy(cntxt->factory);

        BKNI_Free(cntxt);
    }
}

bool piff_parser_scan_movie_info(piff_parser_handle_t handle)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    batom_t piff_container;
    uint32_t box_size = PIFF_PAYLOAD_BUF_SIZE;

    if (!piff_parser_seek_box(handle, cntxt->piff_payload, BMP4_MOVIE, &piff_container, &box_size)) {
        printf("%s: Unable to find moov box\n", __func__);
        return false;
    }

    if (bpiff_parse_moov(&cntxt->piff_mp4, piff_container)) {
        printf("%s: Unable to parse moov box\n", __func__);
        return false;
    }

    return true;
}

bool piff_parser_scan_movie_fragment(piff_parser_handle_t handle, piff_parse_frag_info *frag_info,
        uint8_t *pBuf, uint32_t buffer_size)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    batom_t piff_container;
    bmp4_box mdat;
    uint32_t box_size;

    bpiff_InitMp4FragHeader(&cntxt->piff_mp4_frag);

    /* Search for movie fragment box */
    box_size = buffer_size;

    if (!piff_parser_seek_box(handle, pBuf, BMP4_MOVIE_FRAGMENT, &piff_container, &box_size)) {
        /* printf("%s: Unable to find moof box\n", __func__); */
        return false;
    }

    /* Parse the movie fragment headers */
    if (bpiff_parse_moof(&cntxt->piff_mp4, &cntxt->piff_mp4_frag, piff_container)) {
        printf("%s: Unable to parse moof box\n", __func__);
        return false;
    }

    frag_info->moof_size = box_size;
    box_size = buffer_size - frag_info->moof_size;

    if (!piff_parser_seek_box(handle, pBuf + frag_info->moof_size, BMP4_MOVIE_DATA, &piff_container, &box_size)) {
        printf("%s: Unable to find mdat box\n", __func__);
        return false;
    }

    frag_info->mdat_size = box_size;
    frag_info->trackType = cntxt->piff_mp4_frag.trackType;
    frag_info->trackId = cntxt->piff_mp4_frag.trackId;
    frag_info->sample_info = cntxt->piff_mp4_frag.sample_info;
    frag_info->run_sample_count = cntxt->piff_mp4_frag.run_sample_count;
    frag_info->samples_enc = &cntxt->piff_mp4_frag.samples_enc;

    /* Obtain cursor and set to payload of movie data */
    batom_cursor_from_atom(&frag_info->cursor, piff_container);
    bmp4_parse_box(&frag_info->cursor, &mdat);

    /* Sanity check that cursor is at correct location */
    if (mdat.type != BMP4_MOVIE_DATA)
        return false;

    return true;
}

uint8_t* piff_parser_get_pssh(piff_parser_handle_t handle, size_t *len)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    bpiff_mp4_headers *piff_header;

    if (!cntxt)
        return NULL;

    piff_header = &cntxt->piff_mp4;
    *len = piff_header->psshDataLength;

    return piff_header->pPsshData;
}

uint32_t piff_parser_get_track_type(piff_parser_handle_t handle, uint32_t trackId)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    if (!cntxt)
        return 0;

    return cntxt->piff_mp4.scheme[trackId].trackType;
}

void* piff_parser_get_dec_data(piff_parser_handle_t handle, size_t *len, uint32_t trackId)
{
    struct piff_parser_context *cntxt = (struct piff_parser_context *)handle;
    bpiff_mp4_headers *piff_header;

    if (!cntxt || trackId >= BPIFF_MAX_NB_OF_TRACKS)
        return NULL;

    piff_header = &cntxt->piff_mp4;
    *len = piff_header->scheme[trackId].decConfig.size;

    return (void *)piff_header->scheme[trackId].decConfig.data;
}
