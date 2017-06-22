/*
 * Copyright (c) 2013 Grzegorz Kostka (kostka.grzegorz@gmail.com)
 *
 *
 * HelenOS:
 * Copyright (c) 2012 Martin Sucha
 * Copyright (c) 2012 Frantisek Princ
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
 * @file  ext4_extent.h
 * @brief More complex filesystem functions.
 */
#ifndef EXT4_EXTENT_H_
#define EXT4_EXTENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ext4_config.h>
#include <ext4_types.h>
#include <ext4_misc.h>

#include <ext4_inode.h>

/*
 * Array of ext4_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct ext4_extent_path {
	struct ext4_block block;
	uint16_t depth;
	struct ext4_extent_header *header;
	struct ext4_extent_index *index;
	struct ext4_extent *extent;
};

#define EXT4_EXT_UNWRITTEN_MASK (1L << 15)

#define EXT4_EXT_MAX_LEN_WRITTEN (1L << 15)
#define EXT4_EXT_MAX_LEN_UNWRITTEN \
	(EXT4_EXT_MAX_LEN_WRITTEN - 1)

#define EXT4_EXT_GET_LEN(ex) to_le16((ex)->nblocks)
#define EXT4_EXT_GET_LEN_UNWRITTEN(ex) \
	(EXT4_EXT_GET_LEN(ex) &= ~(EXT4_EXT_UNWRITTEN_MASK))
#define EXT4_EXT_SET_LEN(ex, count) \
	((ex)->nblocks = to_le16(count))

#define EXT4_EXT_IS_UNWRITTEN(ex) \
	(EXT4_EXT_GET_LEN(ex) > EXT4_EXT_MAX_LEN_WRITTEN)
#define EXT4_EXT_SET_UNWRITTEN(ex) \
	((ex)->nblocks |= to_le16(EXT4_EXT_UNWRITTEN_MASK))
#define EXT4_EXT_SET_WRITTEN(ex) \
	((ex)->nblocks &= ~(to_le16(EXT4_EXT_UNWRITTEN_MASK)))

#define EXT4_EXTENT_FIRST(header)                                              \
	((struct ext4_extent *)(((char *)(header)) +                           \
				sizeof(struct ext4_extent_header)))

#define EXT4_EXTENT_FIRST_INDEX(header)                                        \
	((struct ext4_extent_index *)(((char *)(header)) +                     \
				      sizeof(struct ext4_extent_header)))

#define EXT4_EXTENT_LAST(header)                                              \
	((struct ext4_extent *)(((char *)(header)) +                          \
				sizeof(struct ext4_extent_header)) +          \
				(header)->nentries - 1)

#define EXT4_EXTENT_LAST_INDEX(header)                                        \
	((struct ext4_extent_index *)(((char *)(header)) +                    \
				      sizeof(struct ext4_extent_header)) +    \
				      (header)->nentries - 1)

#define EXT4_EXTENT_SIZE sizeof(struct ext4_extent)
#define EXT4_EXTENT_INDEX_SIZE sizeof(struct ext4_extent_index)

#define EXT4_EXTENT_TAIL_OFFSET(hdr)                                           \
	(sizeof(struct ext4_extent_header) +                                   \
	 (sizeof(struct ext4_extent) * to_le16((hdr)->max_nentries)))

#define EXT4_EXTENT_IN_RANGE(iblock, eiblock, len)	\
	((iblock) >= (eiblock) && (iblock) <= (eiblock) + (len) - 1)

#define EXT4_EXTENT_MAX_BLOCKS    ((uint32_t)(-1))

/**@brief Get logical number of the block covered by extent.
 * @param extent Extent to load number from
 * @return Logical number of the first block covered by extent */
static inline uint32_t ext4_extent_get_iblock(struct ext4_extent *extent)
{
	return to_le32(extent->iblock);
}

/**@brief Set logical number of the first block covered by extent.
 * @param extent Extent to set number to
 * @param iblock Logical number of the first block covered by extent */
static inline void ext4_extent_set_iblock(struct ext4_extent *extent,
					  ext4_lblk_t iblock)
{
	extent->iblock = to_le32(iblock);
}

/**@brief Get number of blocks covered by extent.
 * @param extent Extent to load count from
 * @return Number of blocks covered by extent */
static inline uint16_t ext4_extent_get_nblocks(struct ext4_extent *extent)
{
	if (EXT4_EXT_IS_UNWRITTEN(extent))
		return EXT4_EXT_GET_LEN_UNWRITTEN(extent);
	else
		return EXT4_EXT_GET_LEN(extent);
}
/**@brief Set number of blocks covered by extent.
 * @param extent Extent to load count from
 * @param count  Number of blocks covered by extent
 * @param unwritten Whether the extent is unwritten or not */
static inline void
ext4_extent_set_nblocks(struct ext4_extent *extent,
			      uint16_t count, bool unwritten)
{
	EXT4_EXT_SET_LEN(extent, count);
	if (unwritten)
		EXT4_EXT_SET_UNWRITTEN(extent);
}

/**@brief Get physical number of the first block covered by extent.
 * @param extent Extent to load number
 * @return Physical number of the first block covered by extent */
static inline uint64_t ext4_extent_get_fblock(struct ext4_extent *extent)
{
	return ((uint64_t)to_le16(extent->fblock_hi)) << 32 |
			((uint64_t)to_le32(extent->fblock_lo));
}


/**@brief Set physical number of the first block covered by extent.
 * @param extent Extent to load number
 * @param fblock Physical number of the first block covered by extent */
static inline void
ext4_extent_set_fblock(struct ext4_extent *extent, uint64_t fblock)
{
	extent->fblock_lo = to_le32((fblock << 32) >> 32);
	extent->fblock_hi = to_le16((uint16_t)(fblock >> 32));
}


/**@brief Get logical number of the block covered by extent index.
 * @param index Extent index to load number from
 * @return Logical number of the first block covered by extent index */
static inline uint32_t
ext4_extent_index_get_iblock(struct ext4_extent_index *index)
{
	return to_le32(index->iblock);
}

/**@brief Set logical number of the block covered by extent index.
 * @param index  Extent index to set number to
 * @param iblock Logical number of the first block covered by extent index */
static inline void
ext4_extent_index_set_iblock(struct ext4_extent_index *index,
                             uint32_t iblock)
{
	index->iblock = to_le32(iblock);
}

/**@brief Get physical number of block where the child node is located.
 * @param index Extent index to load number from
 * @return Physical number of the block with child node */
static inline uint64_t
ext4_extent_index_get_fblock(struct ext4_extent_index *index)
{
	return ((uint64_t)to_le16(index->fblock_hi)) << 32 |
			((uint64_t)to_le32(index->fblock_lo));
}

/**@brief Set physical number of block where the child node is located.
 * @param index  Extent index to set number to
 * @param fblock Ohysical number of the block with child node */
static inline void ext4_extent_index_set_fblock(struct ext4_extent_index *index,
						uint64_t fblock)
{
	index->fblock_lo = to_le32((fblock << 32) >> 32);
	index->fblock_hi = to_le16((uint16_t)(fblock >> 32));
}

/**@brief Get magic value from extent header.
 * @param header Extent header to load value from
 * @return Magic value of extent header */
static inline uint16_t
ext4_extent_header_get_magic(struct ext4_extent_header *header)
{
	return to_le16(header->magic);
}

/**@brief Set magic value to extent header.
 * @param header Extent header to set value to
 * @param magic  Magic value of extent header */
static inline void ext4_extent_header_set_magic(struct ext4_extent_header *header,
						uint16_t magic)
{
	header->magic = to_le16(magic);
}

/**@brief Get number of entries from extent header
 * @param header Extent header to get value from
 * @return Number of entries covered by extent header */
static inline uint16_t
ext4_extent_header_get_nentries(struct ext4_extent_header *header)
{
	return to_le16(header->nentries);
}

/**@brief Set number of entries to extent header
 * @param header Extent header to set value to
 * @param count  Number of entries covered by extent header */
static inline void
ext4_extent_header_set_nentries(struct ext4_extent_header *header,
				uint16_t count)
{
	header->nentries = to_le16(count);
}

/**@brief Get maximum number of entries from extent header
 * @param header Extent header to get value from
 * @return Maximum number of entries covered by extent header */
static inline uint16_t
ext4_extent_header_get_max_nentries(struct ext4_extent_header *header)
{
	return to_le16(header->max_nentries);
}

/**@brief Set maximum number of entries to extent header
 * @param header    Extent header to set value to
 * @param max_count Maximum number of entries covered by extent header */
static inline void
ext4_extent_header_set_max_nentries(struct ext4_extent_header *header,
					 uint16_t max_count)
{
	header->max_nentries = to_le16(max_count);
}

/**@brief Get depth of extent subtree.
 * @param header Extent header to get value from
 * @return Depth of extent subtree */
static inline uint16_t
ext4_extent_header_get_depth(struct ext4_extent_header *header)
{
	return to_le16(header->depth);
}

/**@brief Set depth of extent subtree.
 * @param header Extent header to set value to
 * @param depth  Depth of extent subtree */
static inline void
ext4_extent_header_set_depth(struct ext4_extent_header *header,
			     uint16_t depth)
{
	header->depth = to_le16(depth);
}

/**@brief Get generation from extent header
 * @param header Extent header to get value from
 * @return Generation */
static inline uint32_t
ext4_extent_header_get_generation(struct ext4_extent_header *header)
{
	return to_le32(header->generation);
}

/**@brief Set generation to extent header
 * @param header     Extent header to set value to
 * @param generation Generation */
static inline void
ext4_extent_header_set_generation(struct ext4_extent_header *header,
				       uint32_t generation)
{
	header->generation = to_le32(generation);
}

/******************************************************************************/

/**TODO:  */
static inline void ext4_extent_tree_init(struct ext4_inode_ref *inode_ref)
{
	/* Initialize extent root header */
	struct ext4_extent_header *header =
			ext4_inode_get_extent_header(inode_ref->inode);
	ext4_extent_header_set_depth(header, 0);
	ext4_extent_header_set_nentries(header, 0);
	ext4_extent_header_set_generation(header, 0);
	ext4_extent_header_set_magic(header, EXT4_EXTENT_MAGIC);

	uint16_t max_entries = (EXT4_INODE_BLOCKS * sizeof(uint32_t) -
				sizeof(struct ext4_extent_header)) /
				sizeof(struct ext4_extent);

	ext4_extent_header_set_max_nentries(header, max_entries);
	inode_ref->dirty  = true;
}



/**@brief Extent-based blockmap manipulation
 * @param inode_ref   I-node
 * @param iblock      starting logical block of the inode
 * @param max_nblocks maximum number of blocks to get from/allocate to blockmap
 * @param resfblockp  return physical block address of the first block of an
 * extent
 * @param create      true if caller wants to insert mapping or convert
 * unwritten mapping to written one
 * @param resnblocksp return number of blocks in an extent (must be smaller than
 * \p max_nblocks)
 * @return Error code*/
int ext4_extent_get_blocks(struct ext4_inode_ref *inode_ref,
			   ext4_lblk_t iblock,
			   ext4_lblk_t max_nblocks,
			   ext4_fsblk_t *resfblockp,
			   bool create,
			   ext4_lblk_t *resnblocksp);


/**@brief Release all data blocks starting from specified logical block.
 * @param inode_ref   I-node to release blocks from
 * @param iblock_from First logical block to release
 * @return Error code */
int ext4_extent_remove_space(struct ext4_inode_ref *inode_ref,
			     ext4_lblk_t from,
			     ext4_lblk_t to);


#ifdef __cplusplus
}
#endif

#endif /* EXT4_EXTENT_H_ */
/**
* @}
*/
