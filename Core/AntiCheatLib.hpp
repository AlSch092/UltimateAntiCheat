#pragma once
#include "../Common/Settings.hpp"

/*
	The PIMPL idiom hides implementation details for static libraries. The actual implementation and members of the class are in DRM.cpp
*/
class AntiCheat final
{
private:
	struct Impl;
	Impl* pImpl;

public:
	explicit AntiCheat(__in Settings* config);

	void Destroy();

	AntiCheat(AntiCheat&&) = delete;
	AntiCheat& operator=(AntiCheat&&) noexcept = default;
	AntiCheat(const AntiCheat&) = delete;
	AntiCheat& operator=(const AntiCheat&) = delete;
};