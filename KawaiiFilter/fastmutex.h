#pragma once
#include <ntddk.h>

class FastMutex {
public:
	void Init();
	void Lock();
	void Unlock();

private:
	FAST_MUTEX _mutex;
};

// Gestor de Mutex RAII 
template<typename TLock>
struct AutoLock {
	AutoLock(TLock& lock) : _lock(lock) {
		lock.Lock();
	}
	~AutoLock() {
		_lock.Unlock();
	}
private:
	TLock& _lock;
};