/******************************************************************************
* (c) 2012-2014 Broadcom Corporation
*
* This program is the proprietary software of Broadcom Corporation and/or its
* licensors, and may only be used, duplicated, modified or distributed pursuant
* to the terms and conditions of a separate, written license agreement executed
* between you and Broadcom (an "Authorized License").  Except as set forth in
* an Authorized License, Broadcom grants no license (express or implied), right
* to use, or waiver of any kind with respect to the Software, and Broadcom
* expressly reserves all rights in and to the Software and all intellectual
* property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU
* HAVE NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY
* NOTIFY BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
*
* Except as expressly set forth in the Authorized License,
*
* 1. This program, including its structure, sequence and organization,
*    constitutes the valuable trade secrets of Broadcom, and you shall use all
*    reasonable efforts to protect the confidentiality thereof, and to use
*    this information only in connection with your use of Broadcom integrated
*    circuit products.
*
* 2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
*    AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
*    WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT
*    TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND ALL IMPLIED
*    WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A
*    PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
*    ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. YOU ASSUME
*    THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
*
* 3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR ITS
*    LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL, INDIRECT,
*    OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY WAY RELATING TO
*    YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN
*    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS
*    OF THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR U.S. $1, WHICHEVER
*    IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING ANY FAILURE OF
*    ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.
******************************************************************************/

#ifndef PIFF_PARSER_H
#define PIFF_PARSER_H

#include "bfile_io.h"
#include "bpiff.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *  piff_parser_handle_t;

typedef struct piff_parse_frag_info {
        batom_cursor cursor;
        uint32_t moof_size;
        uint32_t mdat_size;
        uint32_t trackType;
        uint32_t trackId;
        bmp4_track_fragment_run_sample *sample_info;
        uint32_t run_sample_count;
        bpiff_drm_mp4_se *samples_enc;

} piff_parse_frag_info;

piff_parser_handle_t piff_parser_create(bfile_io_read_t fd);
void piff_parser_destroy(piff_parser_handle_t handle);
bool piff_parser_scan_movie_info(piff_parser_handle_t handle);
bool piff_parser_scan_movie_fragment(piff_parser_handle_t handle,
		piff_parse_frag_info *frag_info,
                uint8_t *pBuf, uint32_t buffer_size);

uint8_t* piff_parser_get_pssh(piff_parser_handle_t handle, size_t *len);
uint32_t piff_parser_get_track_type(piff_parser_handle_t handle, uint32_t trackId);
void* piff_parser_get_dec_data(piff_parser_handle_t handle, size_t *len, uint32_t trackId);

#ifdef __cplusplus
}
#endif
#endif /* PIFF_PARSER_H */
