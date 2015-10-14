/*
 * Copyright (c) 2013 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * - The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @addtogroup lwext4
 * @{
 */
/**
 * @file  ext4_config.h
 * @brief Configuration file.
 */

#ifndef EXT4_CONFIG_H_
#define EXT4_CONFIG_H_

#ifdef CONFIG_HAVE_OWN_CFG
#include <config.h>
#endif

/*****************************************************************************/

#define F_SET_EXT2 2
#define F_SET_EXT3 3
#define F_SET_EXT4 4

#ifndef CONFIG_EXT_FEATURE_SET_LVL
#define CONFIG_EXT_FEATURE_SET_LVL F_SET_EXT4
#endif

/*****************************************************************************/

#if CONFIG_EXT_FEATURE_SET_LVL == F_SET_EXT2
#define CONFIG_DIR_INDEX_ENABLE 0
#define CONFIG_EXTENT_ENABLE 0

/*Superblock features flag*/
#define CONFIG_FEATURE_COMPAT_SUPP EXT2_FEATURE_COMPAT_SUPP

#define CONFIG_FEATURE_INCOMPAT_SUPP                                           \
	(EXT2_FEATURE_INCOMPAT_SUPP | FEATURE_INCOMPAT_IGNORED)

#define CONFIG_FEATURE_RO_COMPAT_SUPP EXT2_FEATURE_RO_COMPAT_SUPP
#elif CONFIG_EXT_FEATURE_SET_LVL == F_SET_EXT3
#define CONFIG_DIR_INDEX_ENABLE 1
#define CONFIG_EXTENT_ENABLE 0

/*Superblock features flag*/
#define CONFIG_FEATURE_COMPAT_SUPP EXT3_FEATURE_COMPAT_SUPP

#define CONFIG_FEATURE_INCOMPAT_SUPP                                           \
	(EXT3_FEATURE_INCOMPAT_SUPP | FEATURE_INCOMPAT_IGNORED)

#define CONFIG_FEATURE_RO_COMPAT_SUPP EXT3_FEATURE_RO_COMPAT_SUPP
#elif CONFIG_EXT_FEATURE_SET_LVL == F_SET_EXT4
#define CONFIG_DIR_INDEX_ENABLE 1
#define CONFIG_EXTENT_ENABLE 1

/*Superblock features flag*/
#define CONFIG_FEATURE_COMPAT_SUPP EXT4_FEATURE_COMPAT_SUPP

#define CONFIG_FEATURE_INCOMPAT_SUPP                                           \
	(EXT4_FEATURE_INCOMPAT_SUPP | FEATURE_INCOMPAT_IGNORED)

#define CONFIG_FEATURE_RO_COMPAT_SUPP EXT4_FEATURE_RO_COMPAT_SUPP
#else
#define "Unsupported CONFIG_EXT_FEATURE_SET_LVL"
#endif

/*****************************************************************************/

/**@brief   Enable directory indexing comb sort*/
#ifndef CONFIG_DIR_INDEX_COMB_SORT
#define CONFIG_DIR_INDEX_COMB_SORT 1
#endif

/**@brief   Include error codes from ext4_errno or standard library.*/
#ifndef CONFIG_HAVE_OWN_ERRNO
#define CONFIG_HAVE_OWN_ERRNO 1
#endif

/**@brief   Debug printf enable (stdout)*/
#ifndef CONFIG_DEBUG_PRINTF
#define CONFIG_DEBUG_PRINTF 1
#endif

/**@brief   Assert printf enable (stdout)*/
#ifndef CONFIG_DEBUG_ASSERT
#define CONFIG_DEBUG_ASSERT 1
#endif

/**@brief   Include assert codes from ext4_debug or standard library.*/
#ifndef CONFIG_HAVE_OWN_ASSERT
#define CONFIG_HAVE_OWN_ASSERT 1
#endif

/**@brief   Statistics of block device*/
#ifndef CONFIG_BLOCK_DEV_ENABLE_STATS
#define CONFIG_BLOCK_DEV_ENABLE_STATS 1
#endif

/**@brief   Cache size of block device.*/
#ifndef CONFIG_BLOCK_DEV_CACHE_SIZE
#define CONFIG_BLOCK_DEV_CACHE_SIZE 8
#endif

/**@brief   Maximum block device count*/
#ifndef CONFIG_EXT4_BLOCKDEVS_COUNT
#define CONFIG_EXT4_BLOCKDEVS_COUNT 2
#endif

/**@brief   Maximum mountpoint count*/
#ifndef CONFIG_EXT4_MOUNTPOINTS_COUNT
#define CONFIG_EXT4_MOUNTPOINTS_COUNT 2
#endif

/**@brief   Include open flags from ext4_errno or standard library.*/
#ifndef CONFIG_HAVE_OWN_OFLAGS
#define CONFIG_HAVE_OWN_OFLAGS 0
#endif

#ifdef __GNUC__
#ifndef __unused
#define __unused __attribute__ ((__unused__))
#endif
#endif

#endif /* EXT4_CONFIG_H_ */

/**
 * @}
 */
