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
 * @file  ext4_types.h
 * @brief Ext4 data structure definitions.
 */

#ifndef EXT4_TYPES_H_
#define EXT4_TYPES_H_

#include "ext4_config.h"
#include "ext4_blockdev.h"
#include "tree.h"

#include <stdint.h>

/*
 * Structure of the super block
 */
struct ext4_sblock {
	uint32_t inodes_count;		   /* I-nodes count */
	uint32_t blocks_count_lo;	  /* Blocks count */
	uint32_t reserved_blocks_count_lo; /* Reserved blocks count */
	uint32_t free_blocks_count_lo;     /* Free blocks count */
	uint32_t free_inodes_count;	/* Free inodes count */
	uint32_t first_data_block;	 /* First Data Block */
	uint32_t log_block_size;	   /* Block size */
	uint32_t log_cluster_size;	 /* Obsoleted fragment size */
	uint32_t blocks_per_group;	 /* Number of blocks per group */
	uint32_t frags_per_group;	  /* Obsoleted fragments per group */
	uint32_t inodes_per_group;	 /* Number of inodes per group */
	uint32_t mount_time;		   /* Mount time */
	uint32_t write_time;		   /* Write time */
	uint16_t mount_count;		   /* Mount count */
	uint16_t max_mount_count;	  /* Maximal mount count */
	uint16_t magic;			   /* Magic signature */
	uint16_t state;			   /* File system state */
	uint16_t errors;		   /* Behavior when detecting errors */
	uint16_t minor_rev_level;	  /* Minor revision level */
	uint32_t last_check_time;	  /* Time of last check */
	uint32_t check_interval;	   /* Maximum time between checks */
	uint32_t creator_os;		   /* Creator OS */
	uint32_t rev_level;		   /* Revision level */
	uint16_t def_resuid;		   /* Default uid for reserved blocks */
	uint16_t def_resgid;		   /* Default gid for reserved blocks */

	/* Fields for EXT4_DYNAMIC_REV superblocks only. */
	uint32_t first_inode;	 /* First non-reserved inode */
	uint16_t inode_size;	  /* Size of inode structure */
	uint16_t block_group_index;   /* Block group index of this superblock */
	uint32_t features_compatible; /* Compatible feature set */
	uint32_t features_incompatible;  /* Incompatible feature set */
	uint32_t features_read_only;     /* Readonly-compatible feature set */
	uint8_t uuid[16];		 /* 128-bit uuid for volume */
	char volume_name[16];		 /* Volume name */
	char last_mounted[64];		 /* Directory where last mounted */
	uint32_t algorithm_usage_bitmap; /* For compression */

	/*
	 * Performance hints. Directory preallocation should only
	 * happen if the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
	 */
	uint8_t s_prealloc_blocks; /* Number of blocks to try to preallocate */
	uint8_t s_prealloc_dir_blocks;  /* Number to preallocate for dirs */
	uint16_t s_reserved_gdt_blocks; /* Per group desc for online growth */

	/*
	 * Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
	uint8_t journal_uuid[16];      /* UUID of journal superblock */
	uint32_t journal_inode_number; /* Inode number of journal file */
	uint32_t journal_dev;	  /* Device number of journal file */
	uint32_t last_orphan;	  /* Head of list of inodes to delete */
	uint32_t hash_seed[4];	 /* HTREE hash seed */
	uint8_t default_hash_version;  /* Default hash version to use */
	uint8_t journal_backup_type;
	uint16_t desc_size;	  /* Size of group descriptor */
	uint32_t default_mount_opts; /* Default mount options */
	uint32_t first_meta_bg;      /* First metablock block group */
	uint32_t mkfs_time;	  /* When the filesystem was created */
	uint32_t journal_blocks[17]; /* Backup of the journal inode */

	/* 64bit support valid if EXT4_FEATURE_COMPAT_64BIT */
	uint32_t blocks_count_hi;	  /* Blocks count */
	uint32_t reserved_blocks_count_hi; /* Reserved blocks count */
	uint32_t free_blocks_count_hi;     /* Free blocks count */
	uint16_t min_extra_isize;    /* All inodes have at least # bytes */
	uint16_t want_extra_isize;   /* New inodes should reserve # bytes */
	uint32_t flags;		     /* Miscellaneous flags */
	uint16_t raid_stride;	/* RAID stride */
	uint16_t mmp_interval;       /* # seconds to wait in MMP checking */
	uint64_t mmp_block;	  /* Block for multi-mount protection */
	uint32_t raid_stripe_width;  /* Blocks on all data disks (N * stride) */
	uint8_t log_groups_per_flex; /* FLEX_BG group size */
	uint8_t reserved_char_pad;
	uint16_t reserved_pad;
	uint64_t kbytes_written; /* Number of lifetime kilobytes written */
	uint32_t snapshot_inum;  /* I-node number of active snapshot */
	uint32_t snapshot_id;    /* Sequential ID of active snapshot */
	uint64_t
	    snapshot_r_blocks_count; /* Reserved blocks for active snapshot's
					future use */
	uint32_t
	    snapshot_list; /* I-node number of the head of the on-disk snapshot
			      list */
	uint32_t error_count;	 /* Number of file system errors */
	uint32_t first_error_time;    /* First time an error happened */
	uint32_t first_error_ino;     /* I-node involved in first error */
	uint64_t first_error_block;   /* Block involved of first error */
	uint8_t first_error_func[32]; /* Function where the error happened */
	uint32_t first_error_line;    /* Line number where error happened */
	uint32_t last_error_time;     /* Most recent time of an error */
	uint32_t last_error_ino;      /* I-node involved in last error */
	uint32_t last_error_line;     /* Line number where error happened */
	uint64_t last_error_block;    /* Block involved of last error */
	uint8_t last_error_func[32];  /* Function where the error happened */
	uint8_t mount_opts[64];
	uint32_t padding[112]; /* Padding to the end of the block */
} __attribute__((packed));

#define EXT4_SUPERBLOCK_MAGIC 0xEF53
#define EXT4_SUPERBLOCK_SIZE 1024
#define EXT4_SUPERBLOCK_OFFSET 1024

#define EXT4_SUPERBLOCK_OS_LINUX 0
#define EXT4_SUPERBLOCK_OS_HURD 1

/*
 * Misc. filesystem flags
 */
#define EXT4_SUPERBLOCK_FLAGS_SIGNED_HASH 0x0001
#define EXT4_SUPERBLOCK_FLAGS_UNSIGNED_HASH 0x0002
#define EXT4_SUPERBLOCK_FLAGS_TEST_FILESYS 0x0004
/*
 * Filesystem states
 */
#define EXT4_SUPERBLOCK_STATE_VALID_FS 0x0001  /* Unmounted cleanly */
#define EXT4_SUPERBLOCK_STATE_ERROR_FS 0x0002  /* Errors detected */
#define EXT4_SUPERBLOCK_STATE_ORPHAN_FS 0x0004 /* Orphans being recovered */

/*
 * Behaviour when errors detected
 */
#define EXT4_SUPERBLOCK_ERRORS_CONTINUE 1 /* Continue execution */
#define EXT4_SUPERBLOCK_ERRORS_RO 2       /* Remount fs read-only */
#define EXT4_SUPERBLOCK_ERRORS_PANIC 3    /* Panic */
#define EXT4_SUPERBLOCK_ERRORS_DEFAULT EXT4_ERRORS_CONTINUE

/*
 * Compatible features
 */
#define EXT4_FEATURE_COMPAT_DIR_PREALLOC 0x0001
#define EXT4_FEATURE_COMPAT_IMAGIC_INODES 0x0002
#define EXT4_FEATURE_COMPAT_HAS_JOURNAL 0x0004
#define EXT4_FEATURE_COMPAT_EXT_ATTR 0x0008
#define EXT4_FEATURE_COMPAT_RESIZE_INODE 0x0010
#define EXT4_FEATURE_COMPAT_DIR_INDEX 0x0020

/*
 * Read-only compatible features
 */
#define EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER 0x0001
#define EXT4_FEATURE_RO_COMPAT_LARGE_FILE 0x0002
#define EXT4_FEATURE_RO_COMPAT_BTREE_DIR 0x0004
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE 0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM 0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK 0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE 0x0040
#define EXT4_FEATURE_RO_COMPAT_QUOTA 0x0100
#define EXT4_FEATURE_RO_COMPAT_BIGALLOC 0x0200
#define EXT4_FEATURE_RO_COMPAT_METADATA_CSUM 0x0400

/*
 * Incompatible features
 */
#define EXT4_FEATURE_INCOMPAT_COMPRESSION 0x0001
#define EXT4_FEATURE_INCOMPAT_FILETYPE 0x0002
#define EXT4_FEATURE_INCOMPAT_RECOVER 0x0004     /* Needs recovery */
#define EXT4_FEATURE_INCOMPAT_JOURNAL_DEV 0x0008 /* Journal device */
#define EXT4_FEATURE_INCOMPAT_META_BG 0x0010
#define EXT4_FEATURE_INCOMPAT_EXTENTS 0x0040 /* extents support */
#define EXT4_FEATURE_INCOMPAT_64BIT 0x0080
#define EXT4_FEATURE_INCOMPAT_MMP 0x0100
#define EXT4_FEATURE_INCOMPAT_FLEX_BG 0x0200
#define EXT4_FEATURE_INCOMPAT_EA_INODE 0x0400	 /* EA in inode */
#define EXT4_FEATURE_INCOMPAT_DIRDATA 0x1000	  /* data in dirent */
#define EXT4_FEATURE_INCOMPAT_BG_USE_META_CSUM 0x2000 /* use crc32c for bg */
#define EXT4_FEATURE_INCOMPAT_LARGEDIR 0x4000	 /* >2GB or 3-lvl htree */
#define EXT4_FEATURE_INCOMPAT_INLINE_DATA 0x8000      /* data in inode */

/*
 * EXT2 supported feature set
 */
#define EXT2_FEATURE_COMPAT_SUPP 0x0000

#define EXT2_FEATURE_INCOMPAT_SUPP                                             \
	(EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_META_BG)

#define EXT2_FEATURE_RO_COMPAT_SUPP                                            \
	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER |                                 \
	 EXT4_FEATURE_RO_COMPAT_LARGE_FILE | EXT4_FEATURE_RO_COMPAT_BTREE_DIR)

/*
 * EXT3 supported feature set
 */
#define EXT3_FEATURE_COMPAT_SUPP (EXT4_FEATURE_COMPAT_DIR_INDEX)

#define EXT3_FEATURE_INCOMPAT_SUPP                                             \
	(EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_META_BG)

#define EXT3_FEATURE_RO_COMPAT_SUPP                                            \
	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER |                                 \
	 EXT4_FEATURE_RO_COMPAT_LARGE_FILE | EXT4_FEATURE_RO_COMPAT_BTREE_DIR)

/*
 * EXT4 supported feature set
 */
#define EXT4_FEATURE_COMPAT_SUPP (EXT4_FEATURE_COMPAT_DIR_INDEX)

#define EXT4_FEATURE_INCOMPAT_SUPP                                             \
	(EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_META_BG |      \
	 EXT4_FEATURE_INCOMPAT_EXTENTS | EXT4_FEATURE_INCOMPAT_FLEX_BG |       \
	 EXT4_FEATURE_INCOMPAT_64BIT)

#define EXT4_FEATURE_RO_COMPAT_SUPP                                            \
	(EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER |                                 \
	 EXT4_FEATURE_RO_COMPAT_LARGE_FILE | EXT4_FEATURE_RO_COMPAT_GDT_CSUM | \
	 EXT4_FEATURE_RO_COMPAT_DIR_NLINK |                                    \
	 EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE |                                  \
	 EXT4_FEATURE_RO_COMPAT_BTREE_DIR | EXT4_FEATURE_RO_COMPAT_HUGE_FILE)

/*Ignored features:
 * RECOVER - journaling in lwext4 is not supported
 *           (probably won't be ever...)
 * MMP - multi-mout protection (impossible scenario)
 * */
#define FEATURE_INCOMPAT_IGNORED                                               \
	EXT4_FEATURE_INCOMPAT_RECOVER | EXT4_FEATURE_INCOMPAT_MMP

#if 0
/*TODO: Features incompatible to implement*/
#define EXT4_FEATURE_INCOMPAT_SUPP
                     (EXT4_FEATURE_INCOMPAT_INLINE_DATA)

/*TODO: Features read only to implement*/
#define EXT4_FEATURE_RO_COMPAT_SUPP
                     EXT4_FEATURE_RO_COMPAT_BIGALLOC |\
                     EXT4_FEATURE_RO_COMPAT_METADATA_CSUM|\
                     EXT4_FEATURE_RO_COMPAT_QUOTA)
#endif

struct ext4_fs {
	struct ext4_blockdev *bdev;
	struct ext4_sblock sb;

	uint64_t inode_block_limits[4];
	uint64_t inode_blocks_per_level[4];

	uint32_t last_inode_bg_id;
};

/* Inode table/bitmap not in use */
#define EXT4_BLOCK_GROUP_INODE_UNINIT 0x0001
/* Block bitmap not in use */
#define EXT4_BLOCK_GROUP_BLOCK_UNINIT 0x0002
/* On-disk itable initialized to zero */
#define EXT4_BLOCK_GROUP_ITABLE_ZEROED 0x0004

/*
 * Structure of a blocks group descriptor
 */
struct ext4_bgroup {
	uint32_t block_bitmap_lo;	    /* Blocks bitmap block */
	uint32_t inode_bitmap_lo;	    /* Inodes bitmap block */
	uint32_t inode_table_first_block_lo; /* Inodes table block */
	uint16_t free_blocks_count_lo;       /* Free blocks count */
	uint16_t free_inodes_count_lo;       /* Free inodes count */
	uint16_t used_dirs_count_lo;	 /* Directories count */
	uint16_t flags;		       /* EXT4_BG_flags (INODE_UNINIT, etc) */
	uint32_t exclude_bitmap_lo;    /* Exclude bitmap for snapshots */
	uint16_t block_bitmap_csum_lo; /* crc32c(s_uuid+grp_num+bbitmap) LE */
	uint16_t inode_bitmap_csum_lo; /* crc32c(s_uuid+grp_num+ibitmap) LE */
	uint16_t itable_unused_lo;     /* Unused inodes count */
	uint16_t checksum;	     /* crc16(sb_uuid+group+desc) */

	uint32_t block_bitmap_hi;	    /* Blocks bitmap block MSB */
	uint32_t inode_bitmap_hi;	    /* I-nodes bitmap block MSB */
	uint32_t inode_table_first_block_hi; /* I-nodes table block MSB */
	uint16_t free_blocks_count_hi;       /* Free blocks count MSB */
	uint16_t free_inodes_count_hi;       /* Free i-nodes count MSB */
	uint16_t used_dirs_count_hi;	 /* Directories count MSB */
	uint16_t itable_unused_hi;	   /* Unused inodes count MSB */
	uint32_t exclude_bitmap_hi;	  /* Exclude bitmap block MSB */
	uint16_t block_bitmap_csum_hi; /* crc32c(s_uuid+grp_num+bbitmap) BE */
	uint16_t inode_bitmap_csum_hi; /* crc32c(s_uuid+grp_num+ibitmap) BE */
	uint32_t reserved;	     /* Padding */
};

struct ext4_block_group_ref {
	struct ext4_block block;
	struct ext4_bgroup *block_group;
	struct ext4_fs *fs;
	uint32_t index;
	bool dirty;
};

#define EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE 32
#define EXT4_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE 64

#define EXT4_MIN_BLOCK_SIZE 1024  /* 1 KiB */
#define EXT4_MAX_BLOCK_SIZE 65536 /* 64 KiB */
#define EXT4_REV0_INODE_SIZE 128

#define EXT4_INODE_BLOCK_SIZE 512

#define EXT4_INODE_DIRECT_BLOCK_COUNT 12
#define EXT4_INODE_INDIRECT_BLOCK EXT4_INODE_DIRECT_BLOCK_COUNT
#define EXT4_INODE_DOUBLE_INDIRECT_BLOCK (EXT4_INODE_INDIRECT_BLOCK + 1)
#define EXT4_INODE_TRIPPLE_INDIRECT_BLOCK (EXT4_INODE_DOUBLE_INDIRECT_BLOCK + 1)
#define EXT4_INODE_BLOCKS (EXT4_INODE_TRIPPLE_INDIRECT_BLOCK + 1)
#define EXT4_INODE_INDIRECT_BLOCK_COUNT                                        \
	(EXT4_INODE_BLOCKS - EXT4_INODE_DIRECT_BLOCK_COUNT)

/*
 * Structure of an inode on the disk
 */
struct ext4_inode {
	uint16_t mode;		    /* File mode */
	uint16_t uid;		    /* Low 16 bits of owner uid */
	uint32_t size_lo;	   /* Size in bytes */
	uint32_t access_time;       /* Access time */
	uint32_t change_inode_time; /* I-node change time */
	uint32_t modification_time; /* Modification time */
	uint32_t deletion_time;     /* Deletion time */
	uint16_t gid;		    /* Low 16 bits of group id */
	uint16_t links_count;       /* Links count */
	uint32_t blocks_count_lo;   /* Blocks count */
	uint32_t flags;		    /* File flags */
	uint32_t unused_osd1;       /* OS dependent - not used in HelenOS */
	uint32_t blocks[EXT4_INODE_BLOCKS]; /* Pointers to blocks */
	uint32_t generation;		    /* File version (for NFS) */
	uint32_t file_acl_lo;		    /* File ACL */
	uint32_t size_hi;
	uint32_t obso_faddr; /* Obsoleted fragment address */

	union {
		struct {
			uint16_t blocks_high;
			uint16_t file_acl_high;
			uint16_t uid_high;
			uint16_t gid_high;
			uint32_t reserved2;
		} linux2;
		struct {
			uint16_t reserved1;
			uint16_t mode_high;
			uint16_t uid_high;
			uint16_t gid_high;
			uint32_t author;
		} hurd2;
	} __attribute__((packed)) osd2;

	uint16_t extra_isize;
	uint16_t pad1;
	uint32_t ctime_extra; /* Extra change time (nsec << 2 | epoch) */
	uint32_t mtime_extra; /* Extra Modification time (nsec << 2 | epoch) */
	uint32_t atime_extra; /* Extra Access time (nsec << 2 | epoch) */
	uint32_t crtime;      /* File creation time */
	uint32_t
	    crtime_extra;    /* Extra file creation time (nsec << 2 | epoch) */
	uint32_t version_hi; /* High 32 bits for 64-bit version */
} __attribute__((packed));

#define EXT4_INODE_MODE_FIFO 0x1000
#define EXT4_INODE_MODE_CHARDEV 0x2000
#define EXT4_INODE_MODE_DIRECTORY 0x4000
#define EXT4_INODE_MODE_BLOCKDEV 0x6000
#define EXT4_INODE_MODE_FILE 0x8000
#define EXT4_INODE_MODE_SOFTLINK 0xA000
#define EXT4_INODE_MODE_SOCKET 0xC000
#define EXT4_INODE_MODE_TYPE_MASK 0xF000

/*
 * Inode flags
 */
#define EXT4_INODE_FLAG_SECRM 0x00000001     /* Secure deletion */
#define EXT4_INODE_FLAG_UNRM 0x00000002      /* Undelete */
#define EXT4_INODE_FLAG_COMPR 0x00000004     /* Compress file */
#define EXT4_INODE_FLAG_SYNC 0x00000008      /* Synchronous updates */
#define EXT4_INODE_FLAG_IMMUTABLE 0x00000010 /* Immutable file */
#define EXT4_INODE_FLAG_APPEND 0x00000020  /* writes to file may only append */
#define EXT4_INODE_FLAG_NODUMP 0x00000040  /* do not dump file */
#define EXT4_INODE_FLAG_NOATIME 0x00000080 /* do not update atime */

/* Compression flags */
#define EXT4_INODE_FLAG_DIRTY 0x00000100
#define EXT4_INODE_FLAG_COMPRBLK                                               \
	0x00000200			   /* One or more compressed clusters */
#define EXT4_INODE_FLAG_NOCOMPR 0x00000400 /* Don't compress */
#define EXT4_INODE_FLAG_ECOMPR 0x00000800  /* Compression error */

#define EXT4_INODE_FLAG_INDEX 0x00001000  /* hash-indexed directory */
#define EXT4_INODE_FLAG_IMAGIC 0x00002000 /* AFS directory */
#define EXT4_INODE_FLAG_JOURNAL_DATA                                           \
	0x00004000			  /* File data should be journaled */
#define EXT4_INODE_FLAG_NOTAIL 0x00008000 /* File tail should not be merged */
#define EXT4_INODE_FLAG_DIRSYNC                                                \
	0x00010000 /* Dirsync behaviour (directories only) */
#define EXT4_INODE_FLAG_TOPDIR 0x00020000    /* Top of directory hierarchies */
#define EXT4_INODE_FLAG_HUGE_FILE 0x00040000 /* Set to each huge file */
#define EXT4_INODE_FLAG_EXTENTS 0x00080000   /* Inode uses extents */
#define EXT4_INODE_FLAG_EA_INODE 0x00200000  /* Inode used for large EA */
#define EXT4_INODE_FLAG_EOFBLOCKS 0x00400000 /* Blocks allocated beyond EOF */
#define EXT4_INODE_FLAG_RESERVED 0x80000000  /* reserved for ext4 lib */

#define EXT4_INODE_ROOT_INDEX 2

struct ext4_inode_ref {
	struct ext4_block block;
	struct ext4_inode *inode;
	struct ext4_fs *fs;
	uint32_t index;
	bool dirty;
};

#define EXT4_DIRECTORY_FILENAME_LEN 255

/**@brief   Directory entry types. */
enum { EXT4_DIRENTRY_UNKNOWN = 0,
       EXT4_DIRENTRY_REG_FILE,
       EXT4_DIRENTRY_DIR,
       EXT4_DIRENTRY_CHRDEV,
       EXT4_DIRENTRY_BLKDEV,
       EXT4_DIRENTRY_FIFO,
       EXT4_DIRENTRY_SOCK,
       EXT4_DIRENTRY_SYMLINK };

union ext4_directory_entry_ll_internal {
	uint8_t name_length_high; /* Higher 8 bits of name length */
	uint8_t inode_type;       /* Type of referenced inode (in rev >= 0.5) */
} __attribute__((packed));

/**
 * Linked list directory entry structure
 */
struct ext4_directory_entry_ll {
	uint32_t inode;	/* I-node for the entry */
	uint16_t entry_length; /* Distance to the next directory entry */
	uint8_t name_length;   /* Lower 8 bits of name length */

	union ext4_directory_entry_ll_internal in;

	uint8_t name[EXT4_DIRECTORY_FILENAME_LEN]; /* Entry name */
} __attribute__((packed));

struct ext4_directory_iterator {
	struct ext4_inode_ref *inode_ref;
	struct ext4_block current_block;
	uint64_t current_offset;
	struct ext4_directory_entry_ll *current;
};

struct ext4_directory_search_result {
	struct ext4_block block;
	struct ext4_directory_entry_ll *dentry;
};

/* Structures for indexed directory */

struct ext4_directory_dx_countlimit {
	uint16_t limit;
	uint16_t count;
};

struct ext4_directory_dx_dot_entry {
	uint32_t inode;
	uint16_t entry_length;
	uint8_t name_length;
	uint8_t inode_type;
	uint8_t name[4];
};

struct ext4_directory_dx_root_info {
	uint32_t reserved_zero;
	uint8_t hash_version;
	uint8_t info_length;
	uint8_t indirect_levels;
	uint8_t unused_flags;
};

struct ext4_directory_dx_entry {
	uint32_t hash;
	uint32_t block;
};

struct ext4_directory_dx_root {
	struct ext4_directory_dx_dot_entry dots[2];
	struct ext4_directory_dx_root_info info;
	struct ext4_directory_dx_entry entries[];
};

struct ext4_fake_directory_entry {
	uint32_t inode;
	uint16_t entry_length;
	uint8_t name_length;
	uint8_t inode_type;
};

struct ext4_directory_dx_node {
	struct ext4_fake_directory_entry fake;
	struct ext4_directory_dx_entry entries[];
};

struct ext4_directory_dx_block {
	struct ext4_block block;
	struct ext4_directory_dx_entry *entries;
	struct ext4_directory_dx_entry *position;
};

#define EXT4_ERR_BAD_DX_DIR (-25000)

#define EXT4_LINK_MAX 65000

#define EXT4_BAD_INO 1
#define EXT4_ROOT_INO 2
#define EXT4_BOOT_LOADER_INO 5
#define EXT4_UNDEL_DIR_INO 6
#define EXT4_RESIZE_INO 7
#define EXT4_JOURNAL_INO 8

#define EXT4_GOOD_OLD_FIRST_INO 11

#define EXT4_EXT_UNWRITTEN_MASK (1L << 15)

#define EXT4_EXT_MAX_LEN_WRITTEN (1L << 15)
#define EXT4_EXT_MAX_LEN_UNWRITTEN \
	(EXT4_EXT_MAX_LEN_WRITTEN - 1)

#define EXT4_EXT_GET_LEN(ex) to_le16((ex)->block_count)
#define EXT4_EXT_GET_LEN_UNWRITTEN(ex) \
	(EXT4_EXT_GET_LEN(ex) &= ~(EXT4_EXT_UNWRITTEN_MASK))
#define EXT4_EXT_SET_LEN(ex, count) \
	((ex)->block_count = to_le16(count))

#define EXT4_EXT_IS_UNWRITTEN(ex) \
	(EXT4_EXT_GET_LEN(ex) > EXT4_EXT_MAX_LEN_WRITTEN)
#define EXT4_EXT_SET_UNWRITTEN(ex) \
	((ex)->block_count |= to_le16(EXT4_EXT_UNWRITTEN_MASK))
#define EXT4_EXT_SET_WRITTEN(ex) \
	((ex)->block_count &= ~(to_le16(EXT4_EXT_UNWRITTEN_MASK)))
/*
 * This is the extent tail on-disk structure.
 * All other extent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid ext4 block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct ext4_extent_tail
{
	uint32_t et_checksum; /* crc32c(uuid+inum+extent_block) */
};

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
struct ext4_extent
{
	uint32_t ee_block;    /* first logical block extent covers */
	uint16_t ee_len;      /* number of blocks covered by extent */
	uint16_t ee_start_hi; /* high 16 bits of physical block */
	uint32_t ee_start_lo; /* low 32 bits of physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct ext4_extent_idx
{
	uint32_t ei_block;   /* index covers logical blocks from 'block' */
	uint32_t ei_leaf_lo; /* pointer to the physical block of the next *
					       * level. leaf or next index could
			      * be there */
	uint16_t ei_leaf_hi; /* high 16 bits of physical block */
	uint16_t ei_unused;
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct ext4_extent_header
{
	uint16_t eh_magic;      /* probably will support different formats */
	uint16_t eh_entries;    /* number of valid entries */
	uint16_t eh_max;	/* capacity of store in entries */
	uint16_t eh_depth;      /* has tree real underlying blocks? */
	uint32_t eh_generation; /* generation of the tree */
};

#define EXT4_EXT_MAGIC (0xf30a)


#define EXT4_EXTENT_MAGIC 0xF30A

#define EXT4_EXTENT_FIRST(header)                                              \
	((struct ext4_extent *)(((char *)(header)) +                           \
				sizeof(struct ext4_extent_header)))

#define EXT4_EXTENT_FIRST_INDEX(header)                                        \
	((struct ext4_extent_index *)(((char *)(header)) +                     \
				      sizeof(struct ext4_extent_header)))

/* EXT3 HTree directory indexing */
#define EXT2_HTREE_LEGACY 0
#define EXT2_HTREE_HALF_MD4 1
#define EXT2_HTREE_TEA 2
#define EXT2_HTREE_LEGACY_UNSIGNED 3
#define EXT2_HTREE_HALF_MD4_UNSIGNED 4
#define EXT2_HTREE_TEA_UNSIGNED 5

#define EXT2_HTREE_EOF 0x7FFFFFFFUL

struct ext4_hash_info {
	uint32_t hash;
	uint32_t minor_hash;
	uint32_t hash_version;
	const uint32_t *seed;
};

/* Extended Attribute(EA) */

/* Magic value in attribute blocks */
#define EXT4_XATTR_MAGIC		0xEA020000

/* Maximum number of references to one attribute block */
#define EXT4_XATTR_REFCOUNT_MAX		1024

/* Name indexes */
#define EXT4_XATTR_INDEX_USER			1
#define EXT4_XATTR_INDEX_POSIX_ACL_ACCESS	2
#define EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT	3
#define EXT4_XATTR_INDEX_TRUSTED		4
#define	EXT4_XATTR_INDEX_LUSTRE			5
#define EXT4_XATTR_INDEX_SECURITY	        6
#define EXT4_XATTR_INDEX_SYSTEM			7
#define EXT4_XATTR_INDEX_RICHACL		8
#define EXT4_XATTR_INDEX_ENCRYPTION		9

struct ext4_xattr_header {
	uint32_t h_magic;	/* magic number for identification */
	uint32_t h_refcount;	/* reference count */
	uint32_t h_blocks;	/* number of disk blocks used */
	uint32_t h_hash;		/* hash value of all attributes */
	uint32_t h_checksum;	/* crc32c(uuid+id+xattrblock) */
				/* id = inum if refcount=1, blknum otherwise */
	uint32_t h_reserved[3];	/* zero right now */
} __attribute__((packed));

struct ext4_xattr_ibody_header {
	uint32_t h_magic;	/* magic number for identification */
} __attribute__((packed));

struct ext4_xattr_entry {
	uint8_t e_name_len;	/* length of name */
	uint8_t e_name_index;	/* attribute name index */
	uint16_t e_value_offs;	/* offset in disk block of value */
	uint32_t e_value_block;	/* disk block attribute is stored on (n/i) */
	uint32_t e_value_size;	/* size of attribute value */
	uint32_t e_hash;		/* hash value of name and value */
} __attribute__((packed));

struct ext4_xattr_item {
	uint8_t name_index;
	char  *name;
	size_t name_len;
	void  *data;
	size_t data_size;

	RB_ENTRY(ext4_xattr_item) node;
};

struct ext4_xattr_ref {
	bool block_loaded;
	struct ext4_block block;
	struct ext4_inode_ref *inode_ref;
	bool   dirty;
	size_t ea_size;
	struct ext4_fs *fs;

	void *iter_arg;
	struct ext4_xattr_item *iter_from;

	RB_HEAD(ext4_xattr_tree,
		ext4_xattr_item) root;
};

#define EXT4_XATTR_ITERATE_CONT 0
#define EXT4_XATTR_ITERATE_STOP 1
#define EXT4_XATTR_ITERATE_PAUSE 2

#define EXT4_GOOD_OLD_INODE_SIZE	128

#define EXT4_XATTR_PAD_BITS		2
#define EXT4_XATTR_PAD		(1<<EXT4_XATTR_PAD_BITS)
#define EXT4_XATTR_ROUND		(EXT4_XATTR_PAD-1)
#define EXT4_XATTR_LEN(name_len) \
	(((name_len) + EXT4_XATTR_ROUND + \
	sizeof(struct ext4_xattr_entry)) & ~EXT4_XATTR_ROUND)
#define EXT4_XATTR_NEXT(entry) \
	((struct ext4_xattr_entry *)( \
	 (char *)(entry) + EXT4_XATTR_LEN((entry)->e_name_len)))
#define EXT4_XATTR_SIZE(size) \
	(((size) + EXT4_XATTR_ROUND) & ~EXT4_XATTR_ROUND)
#define EXT4_XATTR_NAME(entry) \
	((char *)((entry) + 1))

#define EXT4_XATTR_IHDR(raw_inode) \
	((struct ext4_xattr_ibody_header *) \
		((char *)raw_inode + \
		EXT4_GOOD_OLD_INODE_SIZE + \
		(raw_inode)->extra_isize))
#define EXT4_XATTR_IFIRST(hdr) \
	((struct ext4_xattr_entry *)((hdr)+1))

#define EXT4_XATTR_BHDR(block) \
	((struct ext4_xattr_header *)((block)->data))
#define EXT4_XATTR_ENTRY(ptr) \
	((struct ext4_xattr_entry *)(ptr))
#define EXT4_XATTR_BFIRST(block) \
	EXT4_XATTR_ENTRY(EXT4_XATTR_BHDR(block)+1)
#define EXT4_XATTR_IS_LAST_ENTRY(entry) \
	(*(uint32_t *)(entry) == 0)

#define EXT4_ZERO_XATTR_VALUE ((void *)-1)

/*****************************************************************************/

#ifdef CONFIG_BIG_ENDIAN
static inline uint64_t to_le64(uint64_t n)
{
	return ((n & 0xff) << 56) | ((n & 0xff00) << 40) |
		((n & 0xff0000) << 24) | ((n & 0xff000000LL) << 8) |
		((n & 0xff00000000LL) >> 8) | ((n & 0xff0000000000LL) >> 24) |
		((n & 0xff000000000000LL) >> 40) |
		((n & 0xff00000000000000LL) >> 56);
}

static inline uint32_t to_le32(uint32_t n)
{
	return ((n & 0xff) << 24) | ((n & 0xff00) << 8) |
		((n & 0xff0000) >> 8) | ((n & 0xff000000) >> 24);
}

static inline uint16_t to_le16(uint16_t n)
{
	return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

#else
#define to_le64(_n) _n
#define to_le32(_n) _n
#define to_le16(_n) _n
#endif

/****************************Access macros to ext4 structures*****************/

#define ext4_get32(s, f) to_le32((s)->f)
#define ext4_get16(s, f) to_le16((s)->f)
#define ext4_get8(s, f) (s)->f

#define ext4_set32(s, f, v)                                                    \
	do {                                                                   \
		(s)->f = to_le32(v);                                           \
	} while (0)
#define ext4_set16(s, f, v)                                                    \
	do {                                                                   \
		(s)->f = to_le16(v);                                           \
	} while (0)
#define ext4_set8                                                              \
	(s, f, v) do { (s)->f = (v); }                                         \
	while (0)

#endif /* EXT4_TYPES_H_ */

/**
 * @}
 */
