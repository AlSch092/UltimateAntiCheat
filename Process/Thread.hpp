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

	/*  A Thread constructor with only a thread id implies the thread was spawned by some other mechanism than our own code, and we'd like to keep track of it
	*/
	Thread(DWORD id) : Id(id) //Thread classes that call this constructor are ones we aren't creating ourselves to execute code, and rather ones collected in the TLS callback for bookkeeping purposes
	{
		this->ShutdownSignalled = false;
		this->ShouldRunForever = false;
	}

	/* A Thread constructor with enough information to launch a new thread will do so
	*/
	Thread(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, bool shouldRunForever, bool shouldDetach) : ExecutionAddress((UINT_PTR)toExecute), OptionalParam(lpOptionalParam), ShouldRunForever(shouldRunForever), isDetached(shouldDetach)
	{
		if (!BeginExecution(toExecute, lpOptionalParam, shouldRunForever, shouldDetach))
		{
			Logger::logf(Err, "Thread which was scheduled to execute at: %llX failed to spawn", this->ExecutionAddress);

			//std::terminate();  //Optionally, terminate the program since a scheduled thread could not start properly. Integrity cannot be guaranteed if one or more threads fails
		}

		this->ShutdownSignalled = false;
	}

	~Thread()
	{
		Logger::logf(Info, "Ending thread which originally executed at: %llX", this->ExecutionAddress);

		if (this->t.joinable())
		{
			this->ShutdownSignalled = true;

			auto start = std::chrono::high_resolution_clock::now(); //timeout timer

			while (this->t.joinable())
			{

				if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start).count() >= 10)  // If 10 seconds have passed, exit the loop
				{
					Logger::logf(Warning, "Thread did not finish execution within the timeout period.");
					break;
				}

				// Allow the thread some time to finish by sleeping for a short period (you could adjust this as needed)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}

			if (this->t.joinable())
			{
				this->t.join();  //wait for the thread to finish if still running
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
	static bool IsThreadSuspended(DWORD tid);

	void JoinThread() { t.join(); } //since the copy assignment is deleted in std::thread we can't do std::thread getThreadObject() 

	HANDLE GetHandle() const { return this->handle; }
	DWORD GetId() const { return this->Id; }
	auto GetTick() const { return this->Tick; }
	DWORD_PTR GetExecutionAddress() const { return this->ExecutionAddress; }
	LPVOID GetOptionalParameter() const { return this->OptionalParam; }

	bool RunsForever() const { return this->ShouldRunForever; }
	bool IsShutdownSignalled() const { return this->ShutdownSignalled; }

	void SignalShutdown(BOOL toShutdown) { this->ShutdownSignalled = toShutdown; }

	bool BeginExecution(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, bool shouldRunForever, bool shouldDetach);

	void UpdateTick() { this->Tick = std::chrono::steady_clock::now(); }

private:

	std::thread t;

	HANDLE handle = INVALID_HANDLE_VALUE; //assigned to in `BeginExecution`
	DWORD Id = 0; //thread id, assigned to in `BeginExecution` or class constructor

	DWORD_PTR ExecutionAddress = 0;
	LPVOID OptionalParam = nullptr;

	bool isDetached = false;
	bool ShouldRunForever = true;
	std::atomic<bool> ShutdownSignalled;

	std::chrono::steady_clock::time_point Tick; //can be used in cross checks to ensure thread is running as expected. should be updated by the owning thread during execution loops
};