#include "ext4_blockdev.h"
#include "ext4_super.h"
#include "ext4_balloc.h"
#include "ext4_extent.h"
#include "ext4_debug.h"

#include <memory.h>
#include <string.h>
#include <malloc.h>

/*
 * used by extent splitting.
 */
#define EXT4_EXT_MARK_UNWRIT1	0x2  /* mark first half unwritten */
#define EXT4_EXT_MARK_UNWRIT2	0x4  /* mark second half unwritten */

#define EXT4_EXT_DATA_VALID1	0x8  /* first half contains valid data */
#define EXT4_EXT_DATA_VALID2	0x10 /* second half contains valid data */

#define _EXTENTS_TEST
#ifdef _EXTENTS_TEST

#define ext4_inode_to_goal_block(inode) (0)

static inline int ext4_allocate_single_block(struct ext4_inode_ref *inode_ref,
					     ext4_fsblk_t goal __unused,
					     ext4_fsblk_t *blockp)
{
	return ext4_balloc_alloc_block(inode_ref,
			(uint32_t *)blockp);
}

static ext4_fsblk_t ext4_new_meta_blocks(struct ext4_inode_ref *inode_ref,
			ext4_fsblk_t goal,
			unsigned int flags __unused,
			unsigned long *count, int *errp)
{
	ext4_fsblk_t block = 0;

	*errp = ext4_allocate_single_block(inode_ref, goal, &block);
	if (count)
		*count = 1;
	return block;
}

static void ext4_ext_free_blocks(struct ext4_inode_ref *inode_ref,
				 ext4_fsblk_t block, int count __unused, int flags __unused)
{
	ext4_balloc_free_block(inode_ref, (uint32_t)block);
}

#endif

static inline int ext4_ext_space_block(struct ext4_inode_ref *inode_ref)
{
	int size;
	uint32_t block_size = ext4_sb_get_block_size(&inode_ref->fs->sb);

	size = (block_size - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (size > 6)
		size = 6;
#endif
	return size;
}

static inline int ext4_ext_space_block_idx(struct ext4_inode_ref *inode_ref)
{
	int size;
	uint32_t block_size = ext4_sb_get_block_size(&inode_ref->fs->sb);

	size = (block_size - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (size > 5)
		size = 5;
#endif
	return size;
}

static inline int ext4_ext_space_root(struct ext4_inode_ref *inode_ref)
{
	int size;

	size = sizeof(inode_ref->inode->blocks);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (size > 3)
		size = 3;
#endif
	return size;
}

static inline int ext4_ext_space_root_idx(struct ext4_inode_ref *inode_ref)
{
	int size;

	size = sizeof(inode_ref->inode->blocks);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (size > 4)
		size = 4;
#endif
	return size;
}

static int ext4_ext_max_entries(struct ext4_inode_ref *inode_ref,
		unsigned int depth)
{
	int max;

	if (depth == ext_depth(inode_ref->inode)) {
		if (depth == 0)
			max = ext4_ext_space_root(inode_ref);
		else
			max = ext4_ext_space_root_idx(inode_ref);
	} else {
		if (depth == 0)
			max = ext4_ext_space_block(inode_ref);
		else
			max = ext4_ext_space_block_idx(inode_ref);
	}

	return max;
}

static ext4_fsblk_t ext4_ext_find_goal(struct ext4_ext_path *path,
			      ext4_lblk_t block)
{
	if (path) {
		int depth = path->p_depth;
		struct ext4_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		ex = path[depth].p_ext;
		if (ex) {
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
			ext4_lblk_t ext_block = to_le32(ex->ee_block);

			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else
				return ext_pblk - (ext_block - block);
		}

		/* it looks like index is empty;
		 * try to find starting block from index itself */
		if (path[depth].p_bh.lb_id)
			return path[depth].p_bh.lb_id;
	}

	/* OK. use inode's group */
	return ext4_inode_to_goal_block(inode_ref);
}

/*
 * Allocation for a meta data block
 */
static ext4_fsblk_t
ext4_ext_new_meta_block(struct ext4_inode_ref *inode_ref,
			struct ext4_ext_path *path,
			struct ext4_extent *ex, int *err, unsigned int flags)
{
	ext4_fsblk_t goal, newblock;

	goal = ext4_ext_find_goal(path, to_le32(ex->ee_block));
	newblock = ext4_new_meta_blocks(inode_ref, goal, flags,
					NULL, err);
	return newblock;
}

static int __ext4_ext_dirty(struct ext4_inode_ref *inode_ref,
		      struct ext4_ext_path *path)
{
	int err;

	if (path->p_bh.lb_id) {
		/*ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));*/
		/* path points to block */
		err = EOK;
		path->p_bh.dirty = true;
	} else {
		/* path points to leaf/index in inode body */
		err = EOK;
		inode_ref->dirty = true;
	}
	return err;
}

void ext4_ext_drop_refs(struct ext4_inode_ref *inode_ref,
		struct ext4_ext_path *path, int keep_other)
{
	int depth, i;

	if (!path)
		return;
	if (keep_other)
		depth = 0;
	else
		depth = path->p_depth;

	for (i = 0; i <= depth; i++, path++)
		if (path->p_bh.lb_id) {
			ext4_block_set(inode_ref->fs->bdev,
					&path->p_bh);
		}
}

/*
 * Temporarily we don't need to support checksum.
 */
static uint32_t ext4_ext_block_csum(struct ext4_inode_ref *inode_ref __unused,
				    struct ext4_extent_header *eh __unused)
{
	/*return ext4_crc32c(inode->i_csum, eh, EXT4_EXTENT_TAIL_OFFSET(eh));*/
	return 0;
}

static void ext4_extent_block_csum_set(struct ext4_inode_ref *inode_ref,
				    struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *tail;

	tail = find_ext4_extent_tail(eh);
	tail->et_checksum = ext4_ext_block_csum(
			inode_ref, eh);
}

/*
 * Check that whether the basic information inside the extent header
 * is correct or not.
 */
static int ext4_ext_check(struct ext4_inode_ref *inode_ref,
			    struct ext4_extent_header *eh, int depth,
			    ext4_fsblk_t pblk)
{
	struct ext4_extent_tail *tail;
	const char *error_msg;

	if (to_le16(eh->eh_magic) != EXT4_EXT_MAGIC) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (to_le16(eh->eh_depth) != depth) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (eh->eh_max == 0) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	if (to_le16(eh->eh_entries) > to_le16(eh->eh_max)) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}

	tail = find_ext4_extent_tail(eh);
	if (tail->et_checksum != ext4_ext_block_csum(inode_ref, eh)) {
		/* FIXME: Warning: extent checksum damaged? */
	}

	return EOK;

corrupted:
	ext4_dbg(DEBUG_EXTENT, "Bad extents B+ tree block: %s. "
				"Blocknr: %llu\n", error_msg,
				pblk);
	return EIO;
}

static int
read_extent_tree_block(struct ext4_inode_ref *inode_ref,
			ext4_fsblk_t pblk, int depth,
			struct ext4_block *bh, int flags __unused)
{
	int				err;

	err = ext4_block_get(inode_ref->fs->bdev, bh, pblk);
	if (err != EOK)
		goto errout;

	err = ext4_ext_check(inode_ref,
			       ext_block_hdr(bh), depth, pblk);
	if (err != EOK)
		goto errout;

	return EOK;
errout:
	if (bh->lb_id)
		ext4_block_set(inode_ref->fs->bdev, bh);

	return err;
}

/*
 * ext4_ext_binsearch_idx:
 * binary search for the closest index of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch_idx(struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < to_le32(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_idx = l - 1;

}

/*
 * ext4_ext_binsearch:
 * binary search for closest extent of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch(struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < to_le32(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_ext = l - 1;

}

#define EXT4_EXT_PATH_INC_DEPTH 1

int ext4_find_extent(struct ext4_inode_ref *inode_ref,
		ext4_lblk_t block,
		struct ext4_ext_path **orig_path, int flags)
{
	struct ext4_extent_header *eh;
	struct ext4_block bh = {0};
	ext4_fsblk_t buf_block = 0;
	struct ext4_ext_path *path = *orig_path;
	int depth, i, ppos = 0;
	int ret;

	eh = ext_inode_hdr(inode_ref->inode);
	depth = ext_depth(inode_ref->inode);

	if (path) {
		ext4_ext_drop_refs(inode_ref, path, 0);
		if (depth > path[0].p_maxdepth) {
			free(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		int path_depth = depth + EXT4_EXT_PATH_INC_DEPTH;
		/* account possible depth increase */
		path = calloc(1, sizeof(struct ext4_ext_path) *
					(path_depth + 1));
		if (!path)
			return ENOMEM;
		path[0].p_maxdepth = path_depth;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = bh;

	i = depth;
	/* walk through the tree */
	while (i) {
		ext4_ext_binsearch_idx(path + ppos, block);
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_ext = NULL;
		buf_block = path[ppos].p_block;

		i--;
		ppos++;
		if (!path[ppos].p_bh.lb_id ||
		    path[ppos].p_bh.lb_id != buf_block) {
			ret = read_extent_tree_block(inode_ref,
						buf_block, i,
						&bh, flags);
			if (ret != EOK) {
				goto err;
			}
			if (ppos > depth) {
				ext4_block_set(inode_ref->fs->bdev,
						&bh);
				ret = EIO;
				goto err;
			}

			eh = ext_block_hdr(&bh);
			path[ppos].p_bh = bh;
			path[ppos].p_hdr = eh;
		}
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	/* find extent */
	ext4_ext_binsearch(path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	*orig_path = path;

	ret = EOK;
	return ret;

err:
	ext4_ext_drop_refs(inode_ref, path, 0);
	free(path);
	if (orig_path)
		*orig_path = NULL;
	return ret;
}

static void ext4_ext_init_header(struct ext4_inode_ref *inode_ref,
			struct ext4_extent_header *eh, int depth)
{
	eh->eh_entries = 0;
	eh->eh_max = to_le16(ext4_ext_max_entries(inode_ref, depth));
	eh->eh_magic = to_le16(EXT4_EXT_MAGIC);
	eh->eh_depth = depth;
}

/*
 * Be cautious, the buffer_head returned is not yet mark dirtied. */
static int ext4_ext_split_node(struct ext4_inode_ref *inode_ref,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_fsblk_t *sibling,
			       struct ext4_block *new_bh)
{
	int ret;
	ext4_fsblk_t newblock;
	struct ext4_block bh = {0};
	int depth = ext_depth(inode_ref->inode);

	ext4_assert(sibling);

	/* FIXME: currently we split at the point after the current extent. */
	newblock = ext4_ext_new_meta_block(inode_ref, path,
					   newext, &ret, 0);
	if (ret)
		goto cleanup;

	/*  For write access.# */
	ret = ext4_block_get(inode_ref->fs->bdev, &bh, newblock);
	if (ret != EOK)
		goto cleanup;

	if (at == depth) {
		/* start copy from next extent */
		int m = EXT_MAX_EXTENT(path[at].p_hdr) - path[at].p_ext;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(&bh);
		ext4_ext_init_header(inode_ref, neh, 0);
		if (m) {
			struct ext4_extent *ex;
			ex = EXT_FIRST_EXTENT(neh);
			memmove(ex, path[at].p_ext + 1, sizeof(struct ext4_extent) * m);
			neh->eh_entries =
				to_le16(to_le16(neh->eh_entries) + m);
			path[at].p_hdr->eh_entries =
				to_le16(to_le16(path[at].p_hdr->eh_entries) - m);
			ret = __ext4_ext_dirty(inode_ref, path + at);
			if (ret)
				goto cleanup;

		}
	} else {
		int m = EXT_MAX_INDEX(path[at].p_hdr) - path[at].p_idx;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(&bh);
		ext4_ext_init_header(inode_ref, neh, depth - at);
		if (m) {
			struct ext4_extent_idx *ix;
			ix = EXT_FIRST_INDEX(neh);
			memmove(ix, path[at].p_idx + 1, sizeof(struct ext4_extent) * m);
			neh->eh_entries =
				to_le16(to_le16(neh->eh_entries) + m);
			path[at].p_hdr->eh_entries =
				to_le16(to_le16(path[at].p_hdr->eh_entries) - m);
			ret = __ext4_ext_dirty(inode_ref, path + at);
			if (ret)
				goto cleanup;

		}
	}
cleanup:
	if (ret) {
		if (bh.lb_id) {
			ext4_block_set(inode_ref->fs->bdev, &bh);
		}
		if (newblock)
			ext4_ext_free_blocks(inode_ref, newblock, 1, 0);

		newblock = 0;
	}
	*sibling = newblock;
	*new_bh = bh;
	return ret;
}

static ext4_lblk_t ext4_ext_block_index(struct ext4_extent_header *eh)
{
	if (eh->eh_depth)
		return to_le32(EXT_FIRST_INDEX(eh)->ei_block);

	return to_le32(EXT_FIRST_EXTENT(eh)->ee_block);
}

#define EXT_INODE_HDR_NEED_GROW 0x1

struct ext_split_trans {
	ext4_fsblk_t	     ptr;
	struct ext4_ext_path path;
	int		     switch_to;
};

static int ext4_ext_insert_index(struct ext4_inode_ref *inode_ref,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_lblk_t insert_index,
			       ext4_fsblk_t insert_block,
			       struct ext_split_trans *spt)
{
	struct ext4_extent_idx *ix;
	struct ext4_ext_path *curp = path + at;
	struct ext4_block bh = {0};
	int len, err;
	struct ext4_extent_header *eh;

	if (curp->p_idx && insert_index == to_le32(curp->p_idx->ei_block))
		return EIO;

	if (to_le16(curp->p_hdr->eh_entries)
			     == to_le16(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(inode_ref,
						  path, at,
						  newext, &spt->ptr, &bh);
			if (err != EOK)
				goto out;

			neh = ext_block_hdr(&bh);
			if (insert_index >
				to_le32(curp->p_idx->ei_block)) {
				/* Make decision which node should be used to insert the index.*/
				if (to_le16(neh->eh_entries) >
					to_le16(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ix = EXT_LAST_INDEX(eh) + 1;
				} else {
					eh = neh;
					ix = EXT_FIRST_INDEX(eh);
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ix = EXT_LAST_INDEX(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_idx == NULL) {
			ix = EXT_FIRST_INDEX(eh);
			curp->p_idx = ix;
		} else if (insert_index > to_le32(curp->p_idx->ei_block)) {
			/* insert after */
			ix = curp->p_idx + 1;
		} else {
			/* insert before */
			ix = curp->p_idx;
		}
	}

	len = EXT_LAST_INDEX(eh) - ix + 1;
	ext4_assert(len >= 0);
	if (len > 0)
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));

	if (ix > EXT_MAX_INDEX(eh)) {
		err = EIO;
		goto out;
	}

	ix->ei_block = to_le32(insert_index);
	ext4_idx_store_pblock(ix, insert_block);
	eh->eh_entries = to_le16(to_le16(eh->eh_entries) + 1);

	if (ix > EXT_LAST_INDEX(eh)) {
		err = EIO;
		goto out;
	}

	if (eh == curp->p_hdr)
		err = __ext4_ext_dirty(inode_ref, curp);
	else
		err = EOK;

out:
	if (err != EOK) {
		if (bh.lb_id)
			ext4_block_set(inode_ref->fs->bdev, &bh);

		spt->ptr = 0;
	} else if (bh.lb_id) {
		/* If we got a sibling leaf. */
		bh.dirty = true;

		spt->path.p_block = ext4_idx_pblock(ix);
		spt->path.p_depth = to_le16(eh->eh_depth);
		spt->path.p_maxdepth = 0;
		spt->path.p_ext = NULL;
		spt->path.p_idx = ix;
		spt->path.p_hdr = eh;
		spt->path.p_bh = bh;

		/*
		 * If newext->ee_block can be included into the
		 * right sub-tree.
		 */
		if (to_le32(newext->ee_block) >=
			ext4_ext_block_index(ext_block_hdr(&bh)))
			spt->switch_to = 1;
		else {
			curp->p_idx = ix;
			curp->p_block = ext4_idx_pblock(ix);
		}
	
	} else {
		spt->ptr = 0;
		curp->p_idx = ix;
		curp->p_block = ext4_idx_pblock(ix);
	}
	return err;

}

/*
 * ext4_ext_correct_indexes:
 * if leaf gets modified and modified extent is first in the leaf,
 * then we have to correct all indexes above.
 */
static int ext4_ext_correct_indexes(struct ext4_inode_ref *inode_ref,
				    struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode_ref->inode);
	struct ext4_extent *ex;
	uint32_t border;
	int k, err = EOK;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (ex == NULL || eh == NULL) {
		return EIO;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return EOK;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return EOK;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	path[k].p_idx->ei_block = border;
	err = __ext4_ext_dirty(inode_ref, path + k);
	if (err != EOK)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		path[k].p_idx->ei_block = border;
		err = __ext4_ext_dirty(inode_ref, path + k);
		if (err != EOK)
			break;
	}

	return err;
}

static inline int ext4_ext_can_prepend(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex2) + ext4_ext_get_actual_len(ex2)
		!= ext4_ext_pblock(ex1))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_is_unwritten(ex1)) {
		if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_UNWRITTEN_MAX_LEN)
			return 0;
	} else if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (to_le32(ex2->ee_block) + ext4_ext_get_actual_len(ex2) !=
			to_le32(ex1->ee_block))
		return 0;

	return 1;
}

static inline int ext4_ext_can_append(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex1) + ext4_ext_get_actual_len(ex1)
		!= ext4_ext_pblock(ex2))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_is_unwritten(ex1)) {
		if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_UNWRITTEN_MAX_LEN)
			return 0;
	} else if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (to_le32(ex1->ee_block) + ext4_ext_get_actual_len(ex1) !=
			to_le32(ex2->ee_block))
		return 0;

	return 1;
}

static int ext4_ext_insert_leaf(struct ext4_inode_ref *inode_ref,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       struct ext_split_trans *spt)
{
	struct ext4_ext_path *curp = path + at;
	struct ext4_extent *ex = curp->p_ext;
	struct ext4_block bh = {0};
	int len, err = EOK, unwritten;
	struct ext4_extent_header *eh;

	if (curp->p_ext &&
		to_le32(newext->ee_block) == to_le32(curp->p_ext->ee_block))
		return EIO;

	if (curp->p_ext && ext4_ext_can_append(curp->p_ext, newext)) {
		unwritten = ext4_ext_is_unwritten(curp->p_ext);
		curp->p_ext->ee_len = to_le16(ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext));
		if (unwritten)
			ext4_ext_mark_unwritten(curp->p_ext);
		err = __ext4_ext_dirty(inode_ref, curp);
		goto out;

	}

	if (curp->p_ext && ext4_ext_can_prepend(curp->p_ext, newext)) {
		unwritten = ext4_ext_is_unwritten(curp->p_ext);
		curp->p_ext->ee_block = newext->ee_block;
		curp->p_ext->ee_len = to_le16(ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext));
		if (unwritten)
			ext4_ext_mark_unwritten(curp->p_ext);
		err = __ext4_ext_dirty(inode_ref, curp);
		goto out;

	}

	if (to_le16(curp->p_hdr->eh_entries)
			     == to_le16(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(inode_ref, path, at,
						  newext, &spt->ptr, &bh);
			if (err != EOK)
				goto out;

			neh = ext_block_hdr(&bh);
			if (to_le32(newext->ee_block) >
				to_le32(curp->p_ext->ee_block)) {
				if (to_le16(neh->eh_entries) >
					to_le16(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ex = EXT_LAST_EXTENT(eh) + 1;
				} else {
					eh = neh;
					ex = EXT_FIRST_EXTENT(eh);
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ex = EXT_LAST_EXTENT(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_ext == NULL) {
			ex = EXT_FIRST_EXTENT(eh);
			curp->p_ext = ex;
		} else if (to_le32(newext->ee_block) >
				to_le32(curp->p_ext->ee_block)) {
			/* insert after */
			ex = curp->p_ext + 1;
		} else {
			/* insert before */
			ex = curp->p_ext;
		}
	}

	len = EXT_LAST_EXTENT(eh) - ex + 1;
	ext4_assert(len >= 0);
	if (len > 0)
		memmove(ex + 1, ex, len * sizeof(struct ext4_extent));

	if (ex > EXT_MAX_EXTENT(eh)) {
		err = EIO;
		goto out;
	}

	ex->ee_block = newext->ee_block;
	ex->ee_len = newext->ee_len;
	ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
	eh->eh_entries = to_le16(to_le16(eh->eh_entries) + 1);

	if (ex > EXT_LAST_EXTENT(eh)) {
		err = EIO;
		goto out;
	}

	if (eh == curp->p_hdr) {
		err = ext4_ext_correct_indexes(inode_ref, path);
		if (err != EOK)
			goto out;
		err = __ext4_ext_dirty(inode_ref, curp);
	} else
		err = EOK;

out:
	if (err != EOK) {
		if (bh.lb_id)
			ext4_block_set(inode_ref->fs->bdev,
					&bh);

		spt->ptr = 0;
	} else if (bh.lb_id) {
		/* If we got a sibling leaf. */
		bh.dirty = true;

		spt->path.p_block = ext4_ext_pblock(ex);
		spt->path.p_depth = to_le16(eh->eh_depth);
		spt->path.p_maxdepth = 0;
		spt->path.p_ext = ex;
		spt->path.p_idx = NULL;
		spt->path.p_hdr = eh;
		spt->path.p_bh = bh;

		/*
		 * If newext->ee_block can be included into the
		 * right sub-tree.
		 */
		if (to_le32(newext->ee_block) >=
			ext4_ext_block_index(ext_block_hdr(&bh)))
			spt->switch_to = 1;
		else {
			curp->p_ext = ex;
			curp->p_block = ext4_ext_pblock(ex);
		}

	} else {
		spt->ptr = 0;
		curp->p_ext = ex;
		curp->p_block = ext4_ext_pblock(ex);
	}

	return err;

}

/*
 * ext4_ext_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (index block or leaf) into the new block
 * - initializes new top-level, creating index that points to the
 *   just created block
 */
static int ext4_ext_grow_indepth(struct ext4_inode_ref *inode_ref,
				 unsigned int flags)
{
	struct ext4_extent_header *neh;
	struct ext4_block bh = {0};
	ext4_fsblk_t newblock, goal = 0;
	int err = EOK;

	/* Try to prepend new index to old one */
	if (ext_depth(inode_ref->inode))
		goal = ext4_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode_ref->inode)));
	else
		goal = ext4_inode_to_goal_block(inode);

	newblock = ext4_new_meta_blocks(inode_ref, goal, flags,
					NULL, &err);
	if (newblock == 0)
		return err;

	/* # */
	err = ext4_block_get(inode_ref->fs->bdev, &bh, newblock);
	if (err != EOK) {
		ext4_ext_free_blocks(inode_ref, newblock, 1, 0);
		return err;
	}

	/* move top-level index/leaf into new block */
	memmove(bh.data, inode_ref->inode->blocks,
		sizeof(inode_ref->inode->blocks));

	/* set size of new block */
	neh = ext_block_hdr(&bh);
	/* old root could have indexes or leaves
	 * so calculate e_max right way */
	if (ext_depth(inode_ref->inode))
		neh->eh_max = to_le16(ext4_ext_space_block_idx(inode_ref));
	else
		neh->eh_max = to_le16(ext4_ext_space_block(inode_ref));

	neh->eh_magic = to_le16(EXT4_EXT_MAGIC);
	ext4_extent_block_csum_set(inode_ref, neh);

	/* Update top-level index: num,max,pointer */
	neh = ext_inode_hdr(inode_ref->inode);
	neh->eh_entries = to_le16(1);
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		/* Root extent block becomes index block */
		neh->eh_max = to_le16(ext4_ext_space_root_idx(inode_ref));
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	neh->eh_depth = to_le16(to_le16(neh->eh_depth) + 1);

	bh.dirty = true;
	inode_ref->dirty = true;
	ext4_block_set(inode_ref->fs->bdev, &bh);

	return err;
}

void print_path(struct ext4_ext_path *path)
{
	int i = path->p_depth;
	while (i >= 0) {
		ext4_dbg(DEBUG_EXTENT, "depth %d, p_block: %llu, p_ext offset: %d, p_idx offset: %d\n", i,
			path->p_block,
			(path->p_ext)?(path->p_ext - EXT_FIRST_EXTENT(path->p_hdr)):0,
			(path->p_idx)?(path->p_idx - EXT_FIRST_INDEX(path->p_hdr)):0);
		i--;
		path++;
	}
}

static inline void
ext4_ext_replace_path(struct ext4_inode_ref *inode_ref,
		      struct ext4_ext_path *path,
		      struct ext_split_trans *spt,
		      int depth,
		      int level)
{
	int i = depth - level;

	ext4_ext_drop_refs(inode_ref, path + i, 1);
	path[i] = spt->path;
}

int ext4_ext_insert_extent(struct ext4_inode_ref *inode_ref,
		struct ext4_ext_path **ppath,
		struct ext4_extent *newext)
{
	int i, depth, level, ret = EOK;
	ext4_fsblk_t ptr = 0;
	struct ext4_ext_path *path = *ppath;
	struct ext_split_trans *spt = NULL, newblock = {0};

	depth = ext_depth(inode_ref->inode);
	for (i = depth, level = 0;i >= 0;i--, level++)
		if (EXT_HAS_FREE_INDEX(path + i))
			break;

	if (level) {
		spt = calloc(1, sizeof(struct ext_split_trans) * (level));
		if (!spt) {
			ret = ENOMEM;
			goto out;
		}
	}
	i = 0;
again:
	depth = ext_depth(inode_ref->inode);

	do {
		if (!i) {
			ret = ext4_ext_insert_leaf(inode_ref,
					     path, depth - i,
					     newext, &newblock);
		} else {
			ret = ext4_ext_insert_index(inode_ref,
					     path, depth - i,
					     newext, ext4_ext_block_index(spt[i-1].path.p_hdr),
					     spt[i-1].ptr,
					     &newblock);
		}
		ptr = newblock.ptr;

		if (ret && ret != EXT_INODE_HDR_NEED_GROW)
			goto out;
		else if (spt && ptr && !ret) {
			/* Prepare for the next iteration after splitting. */
			spt[i] = newblock;
		}

		i++;
	} while (ptr != 0 && i <= depth);
	
	if (ret == EXT_INODE_HDR_NEED_GROW) {
		ret = ext4_ext_grow_indepth(inode_ref, 0);
		if (ret)
			goto out;
		ret = ext4_find_extent(inode_ref,
				to_le32(newext->ee_block),
				ppath, 0);
		if (ret)
			goto out;
		i = depth;
		path = *ppath;
		goto again;
	}
out:
	if (ret) {
		if (path)
			ext4_ext_drop_refs(inode_ref, path, 0);

		while (--level >= 0 && spt) {
			if (spt[level].ptr) {
				ext4_ext_free_blocks(inode_ref,
					spt[level].ptr, 1, 0);
				ext4_ext_drop_refs(inode_ref,
					&spt[level].path, 1);
			}
		}
	} else {
		while (--level >= 0 && spt) {
			if (spt[level].switch_to)
				ext4_ext_replace_path(inode_ref,
						      path,
						      spt,
						      depth,
						      level);
			else if (spt[level].ptr)
				ext4_ext_drop_refs(inode_ref,
					&spt[level].path, 1);

		}
	}
	if (spt)
		free(spt);

	return ret;
}

static void ext4_ext_remove_blocks(struct ext4_inode_ref *inode_ref,
				struct ext4_extent *ex,
				ext4_lblk_t from, ext4_lblk_t to)
{
	int len = to - from + 1;
	ext4_lblk_t num;
	ext4_fsblk_t start;
	num = from - to_le32(ex->ee_block);
	start = ext4_ext_pblock(ex) + num;
	ext4_dbg(DEBUG_EXTENT, "Freeing %u at %llu, %d\n", from, start, len);
	ext4_ext_free_blocks(inode_ref, start, len, 0);
}

static int ext4_ext_remove_idx(struct ext4_inode_ref *inode_ref,
		struct ext4_ext_path *path, int depth)
{
	int err = EOK, i = depth;
	ext4_fsblk_t leaf;

	/* free index block */
	leaf = ext4_idx_pblock(path[i].p_idx);

	if (path[i].p_idx != EXT_LAST_INDEX(path[i].p_hdr)) {
		int len = EXT_LAST_INDEX(path[i].p_hdr) - path[i].p_idx;
		memmove(path[i].p_idx, path[i].p_idx + 1,
			len * sizeof(struct ext4_extent_idx));
	}

	path[i].p_hdr->eh_entries
		= to_le16(to_le16(path[i].p_hdr->eh_entries) - 1);
	err = __ext4_ext_dirty(inode_ref, path + i);
	if (err != EOK)
		return err;

	ext4_dbg(DEBUG_EXTENT, "IDX: Freeing %u at %llu, %d\n",
		to_le32(path[i].p_idx->ei_block), leaf, 1);
	ext4_ext_free_blocks(inode_ref, leaf, 1, 0);

	while (i > 0) {
		if (path[i].p_idx != EXT_FIRST_INDEX(path[i].p_hdr))
			break;

		path[i-1].p_idx->ei_block = path[i].p_idx->ei_block;
		err = __ext4_ext_dirty(inode_ref, path + i - 1);
		if (err != EOK)
			break;

		i--;
	}
	return err;
}

static int ext4_ext_remove_leaf(struct ext4_inode_ref *inode_ref,
		struct ext4_ext_path *path,
		ext4_lblk_t from, ext4_lblk_t to)
{
	
	int depth = ext_depth(inode_ref->inode);
	struct ext4_extent *ex = path[depth].p_ext;
	struct ext4_extent *start_ex, *ex2 = NULL;
	struct ext4_extent_header *eh = path[depth].p_hdr;
	int len, err = EOK, new_entries;

	start_ex = ex;
	new_entries = to_le16(eh->eh_entries);
	while (ex <= EXT_LAST_EXTENT(path[depth].p_hdr)
		&& to_le32(ex->ee_block) <= to) {
		int new_len = 0;
		int unwritten;
		ext4_fsblk_t start, new_start;
		new_start = start = to_le32(ex->ee_block);
		len = ext4_ext_get_actual_len(ex);
		if (start < from) {
			start = from;
			len -= from - start;
			new_len = from - start;
			start_ex++;
		}
		if (start + len - 1 > to) {
			len -= start + len - 1 - to;
			new_len = start + len - 1 - to;
			new_start += to + 1;
			ex2 = ex;
		}

		ext4_ext_remove_blocks(inode_ref,
				ex, start, start + len - 1);
		ex->ee_block = to_le32(new_start);
		if (!new_len)
			new_entries--;
		else {
			unwritten = ext4_ext_is_unwritten(ex);
			ex->ee_len = to_le16(new_len);
			if (unwritten)
				ext4_ext_mark_unwritten(ex);

		}

		ex += 1;
	}

	if (ex2 == NULL)
		ex2 = ex;

	if (ex2 <= EXT_LAST_EXTENT(eh))
		memmove(start_ex, ex2, EXT_LAST_EXTENT(eh) - ex2 + 1);

	eh->eh_entries = to_le16(new_entries);
	__ext4_ext_dirty(inode_ref, path + depth);
	if (path[depth].p_ext == EXT_FIRST_EXTENT(eh)
		&& eh->eh_entries)
		err = ext4_ext_correct_indexes(inode_ref, path);

	/* if this leaf is free, then we should
	 * remove it from index block above */
	if (err == EOK &&
		eh->eh_entries == 0 && path[depth].p_bh.lb_id)
		err = ext4_ext_remove_idx(inode_ref,
				path, depth - 1);

	return err;
}

static inline int
ext4_ext_more_to_rm(struct ext4_ext_path *path, ext4_lblk_t to)
{
	if (!to_le16(path->p_hdr->eh_entries))
		return 0;

	if (path->p_idx > EXT_LAST_INDEX(path->p_hdr))
		return 0;

	if (to_le32(path->p_idx->ei_block) > to)
		return 0;

	return 1;
}

int ext4_ext_remove_space(struct ext4_inode_ref *inode_ref,
			  ext4_lblk_t from, ext4_lblk_t to)
{
	struct ext4_ext_path *path = NULL;
	int ret = EOK, depth = ext_depth(inode_ref->inode), i;

	ret = ext4_find_extent(inode_ref, from, &path, 0);
	if (ret)
		goto out;

	if (!path[depth].p_ext ||
		!in_range(from, to_le32(path[depth].p_ext->ee_block),
			 ext4_ext_get_actual_len(path[depth].p_ext))) {
		ret = EOK;
		goto out;
	}

	i = depth;
	while (i >= 0) {
		if (i == depth) {
			struct ext4_extent_header *eh;
			struct ext4_extent *first_ex, *last_ex;
			ext4_lblk_t leaf_from, leaf_to;
			eh = path[i].p_hdr;
			ext4_assert(to_le16(eh->eh_entries) > 0);
			first_ex = EXT_FIRST_EXTENT(eh);
			last_ex = EXT_LAST_EXTENT(eh);
			leaf_from = to_le32(first_ex->ee_block);
			leaf_to = to_le32(last_ex->ee_block)
				   + ext4_ext_get_actual_len(last_ex) - 1;
			if (leaf_from < from)
				leaf_from = from;

			if (leaf_to > to)
				leaf_to = to;

			ext4_ext_remove_leaf(inode_ref, path, leaf_from, leaf_to);
			ext4_ext_drop_refs(inode_ref, path + i, 0);
			i--;
			continue;
		} else {
			struct ext4_extent_header *eh;
			eh = path[i].p_hdr;
			if (ext4_ext_more_to_rm(path + i, to)) {
				struct ext4_block bh = {0};
				if (path[i+1].p_bh.lb_id)
					ext4_ext_drop_refs(inode_ref,
						path + i + 1, 0);

				ret = read_extent_tree_block(inode_ref,
					ext4_idx_pblock(path[i].p_idx),
					depth - i - 1, &bh, 0);
				if (ret)
					goto out;

				path[i].p_block = ext4_idx_pblock(path[i].p_idx);
				path[i+1].p_bh = bh;
				path[i+1].p_hdr = ext_block_hdr(&bh);
				path[i+1].p_depth = depth - i - 1;
				if (i + 1 == depth)
					path[i+1].p_ext = EXT_FIRST_EXTENT(path[i+1].p_hdr);
				else
					path[i+1].p_idx = EXT_FIRST_INDEX(path[i+1].p_hdr);

				i++;
			} else {
				if (!eh->eh_entries && i > 0) {
					
					ret = ext4_ext_remove_idx(inode_ref, path, i - 1);
				}
				if (i) {
					ext4_block_set(inode_ref->fs->bdev,
						&path[i].p_bh);
				}
				i--;
			}
		}
	}

	/* TODO: flexible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		ext_inode_hdr(inode_ref->inode)->eh_depth = 0;
		ext_inode_hdr(inode_ref->inode)->eh_max =
			to_le16(ext4_ext_space_root(inode_ref));
		ret = __ext4_ext_dirty(inode_ref, path);
	}

out:
	ext4_ext_drop_refs(inode_ref, path, 0);
	free(path);
	path = NULL;
	return ret;
}

int ext4_ext_split_extent_at(struct ext4_inode_ref *inode_ref,
			     struct ext4_ext_path **ppath,
			     ext4_lblk_t split,
			     int split_flag)
{
	struct ext4_extent *ex, newex;
	ext4_fsblk_t newblock;
	ext4_lblk_t ee_block;
	int ee_len;
	int depth = ext_depth(inode_ref->inode);
	int err = EOK;

	ex = (*ppath)[depth].p_ext;
	ee_block = to_le32(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
	newblock = split - ee_block + ext4_ext_pblock(ex);
	
	if (split == ee_block) {
		/*
		 * case b: block @split is the block that the extent begins with
		 * then we just change the state of the extent, and splitting
		 * is not needed.
		 */
		if (split_flag & EXT4_EXT_MARK_UNWRIT2)
			ext4_ext_mark_unwritten(ex);
		else
			ext4_ext_mark_initialized(ex);

		err = __ext4_ext_dirty(inode_ref, *ppath + depth);
		goto out;
	}

	ex->ee_len = to_le16(split - ee_block);
	if (split_flag & EXT4_EXT_MARK_UNWRIT1)
		ext4_ext_mark_unwritten(ex);

	err = __ext4_ext_dirty(inode_ref, *ppath + depth);
	if (err != EOK)
		goto out;

	newex.ee_block = to_le32(split);
	newex.ee_len   = to_le16(ee_len - (split - ee_block));
	ext4_ext_store_pblock(&newex, newblock);
	if (split_flag & EXT4_EXT_MARK_UNWRIT2)
		ext4_ext_mark_unwritten(&newex);
	err = ext4_ext_insert_extent(inode_ref, ppath, &newex);
	if (err != EOK)
		goto restore_extent_len;

out:
	return err;
restore_extent_len:
	ex->ee_len = to_le16(ee_len);
	err = __ext4_ext_dirty(inode_ref, *ppath + depth);
	return err;
}

static int ext4_ext_convert_to_initialized (
		struct ext4_inode_ref *inode_ref,
		struct ext4_ext_path **ppath,
		ext4_lblk_t split,
		unsigned long blocks)
{
	int depth = ext_depth(inode_ref->inode), err = EOK;
	struct ext4_extent *ex = (*ppath)[depth].p_ext;

	ext4_assert(to_le32(ex->ee_block) <= split);

	if (split + blocks == to_le32(ex->ee_block)
				+ ext4_ext_get_actual_len(ex)) {
		/* split and initialize right part */
		err = ext4_ext_split_extent_at(inode_ref, ppath, split,
				EXT4_EXT_MARK_UNWRIT1);
	} else if (to_le32(ex->ee_block) == split) {
		/* split and initialize left part */
		err = ext4_ext_split_extent_at(inode_ref, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT2);
	} else {
		/* split 1 extent to 3 and initialize the 2nd */
		err = ext4_ext_split_extent_at(inode_ref, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2);
		if (!err) {
			err = ext4_ext_split_extent_at(inode_ref, ppath, split,
					EXT4_EXT_MARK_UNWRIT1);
		}
	}

	return err;
}

int ext4_ext_tree_init(struct ext4_inode_ref *inode_ref)
{
	struct ext4_extent_header *eh;

	eh = ext_inode_hdr(inode_ref->inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = to_le16(EXT4_EXT_MAGIC);
	eh->eh_max = to_le16(ext4_ext_space_root(inode_ref));
	inode_ref->dirty = true;
	return EOK;
}

/*
 * ext4_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
#define EXT_MAX_BLOCKS (ext4_lblk_t)-1

ext4_lblk_t
ext4_ext_next_allocated_block(struct ext4_ext_path *path)
{
	int depth;

	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			/* leaf */
			if (path[depth].p_ext &&
				path[depth].p_ext !=
					EXT_LAST_EXTENT(path[depth].p_hdr))
			  return to_le32(path[depth].p_ext[1].ee_block);
		} else {
			/* index */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return to_le32(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

static int
ext4_ext_zero_unwritten_range(struct ext4_inode_ref *inode_ref,
			      ext4_fsblk_t block,
			      unsigned long blocks_count)
{
	int err = EOK;
	unsigned long i;
	uint32_t block_size = ext4_sb_get_block_size(&inode_ref->fs->sb);
	for (i = 0;i < blocks_count;i++) {
		uint32_t block_u32 = (uint32_t)block + (uint32_t)i;
		struct ext4_block bh = {0};
		err = ext4_block_get(inode_ref->fs->bdev, &bh,
				     block_u32);
		if (err != EOK)
			break;

		memset(bh.data, 0, block_size);
		bh.dirty = true;
		err = ext4_block_set(inode_ref->fs->bdev, &bh);
		if (err != EOK)
			break;

	}
	return err;
}

int ext4_ext_get_blocks(struct ext4_inode_ref *inode_ref,
			ext4_fsblk_t iblock,
			unsigned long max_blocks,
			ext4_fsblk_t *result,
			int create,
			unsigned long *blocks_count)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex;
	int goal, err = EOK, depth;
	unsigned long allocated = 0;
	ext4_fsblk_t next, newblock;

	if (result)
		*result = 0;

	if (blocks_count)
		*blocks_count = 0;

	/* find extent for this block */
	err = ext4_find_extent(inode_ref, iblock, &path, 0);
	if (err != EOK) {
		path = NULL;
		goto out2;
	}

	depth = ext_depth(inode_ref->inode);

	/*
	 * consistent leaf must not be empty
	 * this situations is possible, though, _during_ tree modification
	 * this is why assert can't be put in ext4_ext_find_extent()
	 */
	if ((ex = path[depth].p_ext)) {
	        ext4_lblk_t ee_block = to_le32(ex->ee_block);
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned int ee_len  = ext4_ext_get_actual_len(ex);
		/* if found exent covers block, simple return it */
	        if (in_range(iblock, ee_block, ee_len)) {
			/* number of remain blocks in the extent */
			allocated = ee_len - (iblock - ee_block);
			if (allocated > max_blocks)
				allocated = max_blocks;

			if (ext4_ext_is_unwritten(ex)) {
				if (create) {
					newblock = iblock - ee_block + ee_start;
					err = ext4_ext_zero_unwritten_range(inode_ref,
							newblock,
							1);
					if (err != EOK)
						goto out2;

					err = ext4_ext_convert_to_initialized (
							inode_ref,
							&path,
							iblock,
							allocated);
					if (err != EOK)
						goto out2;

				} else {
					newblock = 0;
				}
			} else {
				newblock = iblock - ee_block + ee_start;
			}
			goto out;
		}
	}

	/*
	 * requested block isn't allocated yet
	 * we couldn't try to create block if create flag is zero
	 */
	if (!create) {
		goto out2;
	}

	/* find next allocated block so that we know how many
	 * blocks we can allocate without ovelapping next extent */
	next = ext4_ext_next_allocated_block(path);
	allocated = next - iblock;
	if (allocated > max_blocks)
		allocated = max_blocks;

	/* allocate new block */
	goal = ext4_ext_find_goal(path, iblock);
	newblock = ext4_new_meta_blocks(inode_ref, goal, 0,
					&allocated, &err);
	if (!newblock)
		goto out2;

	/* try to insert new extent into found leaf and return */
	newex.ee_block = to_le32(iblock);
	ext4_ext_store_pblock(&newex, newblock);
	newex.ee_len = to_le16(allocated);
	err = ext4_ext_insert_extent(inode_ref, &path, &newex);
	if (err != EOK) {
		/* free data blocks we just allocated */
		ext4_ext_free_blocks(inode_ref,
				ext4_ext_pblock(&newex),
				to_le16(newex.ee_len), 0);
		goto out2;
	}

	/* previous routine could use block we allocated */
	newblock = ext4_ext_pblock(&newex);

out:
	if (allocated > max_blocks)
		allocated = max_blocks;

	if (result)
		*result = newblock;

	if (blocks_count)
		*blocks_count = allocated;

out2:
	if (path) {
		ext4_ext_drop_refs(inode_ref, path, 0);
		free(path);
	}

	return err;
}
