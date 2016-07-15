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
 * @file  ext4.h
 * @brief Ext4 high level operations (files, directories, mount points...).
 *        Client has to include only this file.
 */

#ifndef EXT4_H_
#define EXT4_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include "ext4_config.h"
#include "ext4_types.h"
#include "ext4_errno.h"
#include "ext4_oflags.h"
#include "ext4_debug.h"

#include "ext4_blockdev.h"

/********************************OS LOCK INFERFACE***************************/

/**@brief   OS dependent lock interface.*/
struct ext4_lock {

	/**@brief   Lock access to mount point*/
	void (*lock)(void);

	/**@brief   Unlock access to mount point*/
	void (*unlock)(void);
};

/********************************FILE DESCRIPTOR*****************************/

/**@brief   File descriptor*/
typedef struct ext4_file {

	/**@brief   Mount point handle.*/
	struct ext4_mountpoint *mp;

	/**@brief   File inode id*/
	uint32_t inode;

	/**@brief   Open flags.*/
	uint32_t flags;

	/**@brief   File size.*/
	uint64_t fsize;

	/**@brief   File position*/
	uint64_t fpos;
} ext4_file;

/*****************************DIRECTORY DESCRIPTOR***************************/

/**@brief   Directory entry descriptor. Copy from ext4_types.h*/
typedef struct ext4_direntry {
	uint32_t inode;
	uint16_t entry_length;
	uint8_t name_length;
	uint8_t inode_type;
	uint8_t name[255];
} ext4_direntry;

typedef struct ext4_dir {
	/**@brief   File descriptor*/
	ext4_file f;
	/**@brief   Current directory entry.*/
	ext4_direntry de;
	/**@brief   Next entry offset*/
	uint64_t next_off;
} ext4_dir;

/********************************MOUNT OPERATIONS****************************/

/**@brief   Mount a block device with EXT4 partition to the mount point.
 * @param   bdev block device
 * @param   read_only mount as read-only mode
 * @param   mountpoint the output mountpoint structure if this call succeeds
 *
 * @return standard error code */
int ext4_mount(struct ext4_blockdev *bdev, bool read_only,
	       void **mountpoint);

/**@brief   Umount operation.
 * @param   mountpoint mountpoint structure
 * @return  standard error code */
int ext4_umount(void *mp);

/**@brief   Start journaling. Journaling start/stop functions are transparent
 *          and might be used on filesystems without journaling support.
 * @warning Usage:
 *              ext4_mount("sda1", "/");
 *              ext4_journal_start("/");
 *
 *              //File operations here...
 *
 *              ext4_journal_stop("/");
 *              ext4_umount("/");
 * @param   mountpoint mountpoint structure
 * @return  standard error code */
int ext4_journal_start(void *mountpoint);

/**@brief   Stop journaling. Journaling start/stop functions are transparent
 *          and might be used on filesystems without journaling support.
 * @param   mountpoint mountpoint structure
 * @return  standard error code */
int ext4_journal_stop(void *mountpoint);

/**@brief   Journal recovery.
 * @param   mountpoint mountpoint structure
 * @warning Must be called after @ref ext4_mount
 * @return standard error code */
int ext4_recover(void *mountpoint);

/**@brief   Some of the filesystem stats.*/
struct ext4_mount_stats {
	uint32_t inodes_count;
	uint32_t free_inodes_count;
	uint64_t blocks_count;
	uint64_t free_blocks_count;

	uint32_t block_size;
	uint32_t block_group_count;
	uint32_t blocks_per_group;
	uint32_t inodes_per_group;

	char volume_name[16];
};

/**@brief   Get file system params.
 * @param   mountpoint mountpoint structure
 * @param   stats ext fs stats
 * @return  standard error code */
int ext4_mount_point_stats(void *mountpoint,
			   struct ext4_mount_stats *stats);

/**@brief   Setup OS lock routines.
 * @param   mountpoint mountpoint structure
 * @param   locks - lock and unlock functions
 * @return  standard error code */
int ext4_mount_setup_locks(void *mountpoint,
			   const struct ext4_lock *locks);

/**@brief   Acquire the filesystem superblock pointer of a mp.
 * @param   mountpoint mountpoint structure
 * @param   superblock pointer
 * @return  standard error code */
int ext4_get_sblock(void *mountpoint, struct ext4_sblock **sb);

/**@brief   Enable/disable write back cache mode.
 * @warning Default model of cache is write trough. It means that when You do:
 *
 *          ext4_fopen(...);
 *          ext4_fwrie(...);
 *                           < --- data is flushed to physical drive
 *
 *          When you do:
 *          ext4_cache_write_back(..., 1);
 *          ext4_fopen(...);
 *          ext4_fwrie(...);
 *                           < --- data is NOT flushed to physical drive
 *          ext4_cache_write_back(..., 0);
 *                           < --- when write back mode is disabled all
 *                                 cache data will be flushed
 * To enable write back mode permanently just call this function
 * once after ext4_mount (and disable before ext4_umount).
 *
 * Some of the function use write back cache mode internally.
 * If you enable write back mode twice you have to disable it twice
 * to flush all data:
 *
 *      ext4_cache_write_back(..., 1);
 *      ext4_cache_write_back(..., 1);
 *
 *      ext4_cache_write_back(..., 0);
 *      ext4_cache_write_back(..., 0);
 *
 * Write back mode is useful when you want to create a lot of empty
 * files/directories.
 *
 * @param   mountpoint mountpoint structure
 * @param   on enable/disable
 *
 * @return  standard error code */
int ext4_cache_write_back(void *mountpoint, bool on);

/********************************FILE OPERATIONS*****************************/

/**@brief   Remove file by path.
 * @param   mountpoint mountpoint structure
 * @param   path path to file
 * @return  standard error code */
int ext4_fremove(void *mountpoint, const char *path);

/**@brief   create a hardlink for a file.
 * @param   mountpoint mountpoint structure
 * @param   path path to file
 * @param   hardlink_path path of hardlink
 * @return  standard error code */
int ext4_flink(void *mountpoint,
	       const char *path, const char *hardlink_path);

/**@brief Rename file
 * @param mountpoint mountpoint structure
 * @param path source
 * @param new_path destination
 * @return  standard error code */
int ext4_frename(void *mountpoint,
		 const char *path, const char *new_path);

/**@brief   File open function.
 * @param   mountpoint mountpoint structure
 * @param   path filename (has to start from mount point)
 *          /my_partition/my_file
 * @param   flags open file flags
 *  |---------------------------------------------------------------|
 *  |   r or rb                 O_RDONLY                            |
 *  |---------------------------------------------------------------|
 *  |   w or wb                 O_WRONLY|O_CREAT|O_TRUNC            |
 *  |---------------------------------------------------------------|
 *  |   a or ab                 O_WRONLY|O_CREAT|O_APPEND           |
 *  |---------------------------------------------------------------|
 *  |   r+ or rb+ or r+b        O_RDWR                              |
 *  |---------------------------------------------------------------|
 *  |   w+ or wb+ or w+b        O_RDWR|O_CREAT|O_TRUNC              |
 *  |---------------------------------------------------------------|
 *  |   a+ or ab+ or a+b        O_RDWR|O_CREAT|O_APPEND             |
 *  |---------------------------------------------------------------|
 *
 * @return  standard error code*/
int ext4_fopen(void *mountpoint,
	       ext4_file *f, const char *path, const char *flags);

/**@brief   Alternate file open function.
 * @param   mountpoint mountpoint structure
 * @param   filename, (has to start from mount point)
 *          /my_partition/my_file
 * @param   flags open file flags
 * @return  standard error code*/
int ext4_fopen2(void *mountpoint,
		ext4_file *f, const char *path, int flags);

/**@brief   File close function.
 * @param   f file handle
 * @return  standard error code*/
int ext4_fclose(ext4_file *f);

/**@brief   Fill in the ext4_inode buffer.
 * @param   mountpoint mountpoint structure
 * @param   path fetch inode data of the path
 * @param   ret_ino the inode id of the path
 * @param   ext4_inode buffer
 * @return  standard error code*/
int ext4_fill_raw_inode(void *mountpoint,
			const char *path, uint32_t *ret_ino,
			struct ext4_inode *inode);

/**@brief   File truncate function.
 * @param   f file handle
 * @param   new file size
 * @return  standard error code*/
int ext4_ftruncate(ext4_file *f, uint64_t size);

/**@brief   Read data from file.
 * @param   f file handle
 * @param   buf output buffer
 * @param   size bytes to read
 * @param   rcnt bytes read (may be NULL)
 * @return  standard error code*/
int ext4_fread(ext4_file *f, void *buf, size_t size, size_t *rcnt);

/**@brief   Write data to file.
 * @param   f file handle
 * @param   buf data to write
 * @param   size write length
 * @param   wcnt bytes written (may be NULL)
 * @return  standard error code*/
int ext4_fwrite(ext4_file *f, const void *buf, size_t size, size_t *wcnt);

/**@brief   File seek operation.
 * @param   f file handle
 * @param   offset offset to seek
 * @param   origin seek type:
 *              @ref SEEK_SET
 *              @ref SEEK_CUR
 *              @ref SEEK_END
 * @return  standard error code*/
int ext4_fseek(ext4_file *f, uint64_t offset, uint32_t origin);

/**@brief   Get file position.
 * @param   f file handle
 * @return  actual file position */
uint64_t ext4_ftell(ext4_file *f);

/**@brief   Get file size.
 * @param   f file handle
 * @return  file size */
uint64_t ext4_fsize(ext4_file *f);

/**@brief Change file/directory/link mode bits
 * @param mountpoint mountpoint structure
 * @param path to file/dir/link
 * @param mode new mode bits (for example 0777)
 * @return  standard error code*/
int ext4_chmod(void *mountpoint, const char *path, uint32_t mode);

/**@brief Change file owner and group
 * @param mountpoint mountpoint structure
 * @param path to file/dir/link
 * @param uid user id
 * @param gid group id
 * @return  standard error code*/
int ext4_chown(void *mountpoint,
	       const char *path, uint32_t uid, uint32_t gid);

/**@brief Set file access time
 * @param mountpoint mountpoint structure
 * @param path to file/dir/link
 * @param atime access timestamp
 * @return  standard error code*/
int ext4_file_set_atime(void *mountpoint,
			const char *path, uint32_t atime);

/**@brief Set file modify time
 * @param mountpoint mountpoint structure
 * @param path to file/dir/link
 * @param mtime modify timestamp
 * @return  standard error code*/
int ext4_file_set_mtime(void *mountpoint,
			const char *path, uint32_t mtime);

/**@brief Set file change time
 * @param mountpoint mountpoint structure
 * @param path to file/dir/link
 * @param ctime change timestamp
 * @return  standard error code*/
int ext4_file_set_ctime(void *mountpoint,
			const char *path, uint32_t ctime);

/**@brief Create symbolic link
 * @param mountpoint mountpoint structure
 * @param target destination path
 * @param path source entry
 * @return standard error code*/
int ext4_fsymlink(void *mountpoint,
		  const char *target, const char *path);

/**@brief Create special file
 * @param mountpoint mountpoint structure
 * @param path path to new file
 * @param filetype The filetype of the new special file
 * 	  (that must not be regular file, directory, or unknown type)
 * @param dev if filetype is char device or block device,
 * 	  the device number will become the payload in the inode
 * @return standard error code*/
int ext4_mknod(void *mountpoint,
	       const char *path, int filetype, uint32_t dev);

/**@brief Read symbolic link payload
 * @param mountpoint mountpoint structure
 * @param path to symlink
 * @param buf output buffer
 * @param bufsize output buffer max size
 * @param rcnt bytes read
 * @return standard error code*/
int ext4_readlink(void *mountpoint,
		  const char *path, char *buf, size_t bufsize, size_t *rcnt);

/**@brief Set extended attribute
 * @param mountpoint mountpoint structure
 * @param path to file/directory
 * @param name name of the entry to add
 * @param name_len length of @name in bytes
 * @param data data of the entry to add
 * @param data_size size of data to add
 * @param replace this boolean is deprecated.
 * @return standard error code*/
int ext4_setxattr(void *mountpoint,
		  const char *path, const char *name, size_t name_len,
		  const void *data, size_t data_size, bool replace);

/**@brief Get extended attribute
 * @param mountpoint mountpoint structure
 * @param path to file/directory
 * @param name name of the entry to get
 * @param name_len length of @name in bytes
 * @param data data of the entry to get
 * @param data_size size of data to get
 * @return standard error code*/
int ext4_getxattr(void *mountpoint,
		  const char *path, const char *name, size_t name_len,
		  void *buf, size_t buf_size, size_t *data_size);

/**@brief List extended attributes
 * @param mountpoint mountpoint structure
 * @param path to file/directory
 * @param list list to hold the name of entries
 * @param size size of @list in bytes
 * @param ret_size used bytes of @list
 * @return standard error code*/
int ext4_listxattr(void *mountpoint,
		   const char *path, char *list, size_t size, size_t *ret_size);

/**@brief Remove extended attribute
 * @param mountpoint mountpoint structure
 * @param path to file/directory
 * @param name name of the entry to remove
 * @param name_len length of @name in bytes
 * @return standard error code*/
int ext4_removexattr(void *mountpoint,
		     const char *path, const char *name, size_t name_len);


/*********************************DIRECTORY OPERATION***********************/

/**@brief   Remove directory.
 * @param   mountpoint mountpoint structure
 * @param   path directory path to remove
 * @return  standard error code*/
int ext4_dir_rm(void *mountpoint, const char *path);

/**@brief Rename/move directory
 * @param mountpoint mountpoint structure
 * @param path source
 * @param new_path destination
 * @return  standard error code */
int ext4_dir_mv(void *mountpoint,
		const char *path, const char *new_path);

/**@brief   Create new directory.
 * @param   mountpoint mountpoint structure
 * @param   name new directory name
 * @return  standard error code*/
int ext4_dir_mk(void *mountpoint, const char *path);

/**@brief   Directory open.
 * @param   mountpoint mountpoint structure
 * @param   d directory handle
 * @param   path directory path
 * @return  standard error code*/
int ext4_dir_open(void *mountpoint,
		  ext4_dir *d, const char *path);

/**@brief   Directory close.
 * @param   d directory handle
 * @return  standard error code*/
int ext4_dir_close(ext4_dir *d);

/**@brief   Return next directory entry.
 * @param   d directory handle
 * @param   id entry id
 * @return  directory entry id (NULL if no entry)*/
const ext4_direntry *ext4_dir_entry_next(ext4_dir *d);

/**@brief   Rewine directory entry offset.
 * @param   d directory handle*/
void ext4_dir_entry_rewind(ext4_dir *d);


#ifdef __cplusplus
}
#endif

#endif /* EXT4_H_ */

/**
 * @}
 */
