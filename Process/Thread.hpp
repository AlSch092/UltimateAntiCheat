//By AlSch092 @ Github
#pragma once
#include <windows.h>
#include <chrono>
#include <thread>
#include "../Common/Logger.hpp"

/*
	The `Thread` class is a RAII wrapper around std::thread, providing additional functionality for thread management
*/
class Thread
{
public:

	Thread(DWORD id) : Id(id) //Thread classes that call this constructor are ones we aren't creating ourselves to execute code, and rather ones collected in the TLS callback for bookkeeping purposes
	{
		this->ShutdownSignalled = false;
		this->ShouldRunForever = false;
	}

	Thread(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever) : ExecutionAddress((UINT_PTR)toExecute), OptionalParam(lpOptionalParam), ShouldRunForever(shouldRunForever)
	{
		BeginExecution(toExecute, lpOptionalParam, shouldRunForever);
		this->ShutdownSignalled = false;
	}

	~Thread()
	{
		Logger::logf("UltimateAnticheat.log", Info, "Ending thread which originally executed at: %llX", this->ExecutionAddress);

		if (this->t.native_handle() != INVALID_HANDLE_VALUE)
		{
			this->ShutdownSignalled = true;

			WaitForSingleObject(this->t.native_handle(), 10000); //wait for thread to end, we'll give them 10 seconds max
		}
	}

	Thread(Thread&&) = delete;  //delete move constructr
	Thread& operator=(Thread&&) noexcept = default; //delete move assignment operator

	Thread(const Thread&) = delete; //delete copy constructor 
	Thread& operator=(const Thread&) = delete; //delete assignment operator

	Thread operator+(Thread&) = delete; //delete all arithmetic operators, unnecessary for context
	Thread operator-(Thread&) = delete;
	Thread operator*(Thread&) = delete;
	Thread operator/(Thread&) = delete;

	static bool IsThreadRunning(HANDLE threadHandle); //these could potentially go into Process.hpp/cpp, since we have one Thread class for each thread, thus a static function is not as well suited to be here
	static bool IsThreadSuspended(HANDLE threadHandle);

	HANDLE GetHandle() const { return handle; }
	DWORD GetId() const { return this->Id; }
	auto GetTick() const { return this->Tick; }
	DWORD_PTR GetExecutionAddress() const { return this->ExecutionAddress; }
	LPVOID GetOptionalParameter() const { return this->OptionalParam; }

	BOOL RunsForever() const { return this->ShouldRunForever; }
	BOOL IsShutdownSignalled() const { return this->ShutdownSignalled; }
	void SignalShutdown(BOOL toShutdown) { this->ShutdownSignalled = toShutdown; }

	BOOL BeginExecution(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever);

	void UpdateTick() { this->Tick = std::chrono::steady_clock::now(); }

private:

	std::thread t;

	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD Id = 0; //thread id

	UINT64 ExecutionAddress = 0;
	LPVOID OptionalParam = nullptr;

	BOOL ShouldRunForever;
	std::atomic<bool> ShutdownSignalled;

	std::chrono::steady_clock::time_point Tick; //used in cross checks to ensure thread is running as expected. should be incremented by the thread itself during execution
};
