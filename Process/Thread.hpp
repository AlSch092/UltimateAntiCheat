//By AlSch092 @ Github
#pragma once
#include <windows.h>
#include <chrono>
#include "../Common/Logger.hpp"

/*
	Thread class represents a process thread, we aim to track threads in our process such that we can determine possible rogue threads
	Any helper functions related to threads are also defined in this class
*/
class Thread final
{
public:

	Thread(DWORD id) : Id(id) //Thread classes that call this constructor are ones we aren't creating ourselves to execute code, and rather ones collected in the TLS callback for bookkeeping purposes
	{
		this->ShutdownSignalled = false;
		this->ShouldRunForever = false;
	}

	Thread(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever) : ExecutionAddress((UINT_PTR)toExecute), OptionalParam(lpOptionalParam), ShouldRunForever(shouldRunForever)
	{	
		if (BeginExecution((DWORD_PTR)toExecute, lpOptionalParam, shouldRunForever))
		{
			Logger::logf("UltimateAnticheat.log", Err, "Failed to create new thread @ Thread::Thread - address %llX", (UINT_PTR)toExecute);
		}
	}

	~Thread()
	{
		Logger::logf("UltimateAnticheat.log", Info, "Ending thread which originally executed at: %llX", this->ExecutionAddress);

		if (this->handle != INVALID_HANDLE_VALUE)
		{
			this->ShutdownSignalled = true;

			if (!TerminateThread(this->handle, 0)) //end thread immediately instead of signalling it to end and then using WaitForSingleObject
			{
				Logger::logf("UltimateAnticheat.log", Warning, "TerminateThread failed @ ~Thread");
			}
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

	HANDLE GetHandle() const { return this->handle; }
	DWORD GetId() const { return this->Id; }
	DWORD_PTR GetExecutionAddress() const { return this->ExecutionAddress; }
	LPVOID GetOptionalParameter() const { return this->OptionalParam; }
	auto GetTick() const { return this->Tick; }
	BOOL RunsForever() const { return this->ShouldRunForever; }
	BOOL IsShutdownSignalled() const { return this->ShutdownSignalled; }
	
	void SignalShutdown(BOOL toShutdown) { this->ShutdownSignalled = toShutdown; }

	BOOL BeginExecution();
	BOOL BeginExecution(DWORD_PTR toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever);

	void UpdateTick() { this->Tick = std::chrono::steady_clock::now(); }

private:

	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD Id = 0; //thread id

	DWORD_PTR ExecutionAddress = 0;
	LPVOID OptionalParam = nullptr;

	BOOL ShouldRunForever = false;
	BOOL ShutdownSignalled = false;

	std::chrono::steady_clock::time_point Tick; //used in cross checks to ensure thread is running as expected. should be incremented by the thread itself during execution
};
