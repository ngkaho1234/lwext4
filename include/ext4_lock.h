#ifndef EXT4_LOCK_H_
#define EXT4_LOCK_H_

/**@brief   OS dependent mutex interface.*/
struct ext4_mutex {

	/**@brief   Mutex allocation interface*/
	void *(*alloc)(void);

	/**@brief   Mutex deallocation interface*/
	void (*free)(void *mutex);

	/**@brief   Lock routine*/
	void (*lock)(void *mutex);

	/**@brief   Unlock routine*/
	void (*unlock)(void *mutex);
};

struct ext4_rwlock {

	/**@brief   Mutex allocation interface*/
	void *(*alloc)(void);

	/**@brief   Mutex deallocation interface*/
	void (*free)(void *mutex);

	/**@brief   Shared lock routine*/
	void (*read)(void *mutex);

	/**@brief   Exclusive lock routine*/
	void (*write)(void *mutex);

	/**@brief   Shared unlock routine*/
	void (*read_unlock)(void *mutex);

	/**@brief   Exclusive unlock routine*/
	void (*write_unlock)(void *mutex);
};

extern struct ext4_mutex ext4_mutex;
extern struct ext4_rwlock ext4_rwlock;

#endif /* EXT4_LOCK_H_ */
