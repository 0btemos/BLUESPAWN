#pragma once

#include "scan/Scanner.h"

class RegistryScanner : public Scanner {
public:
	virtual std::vector<std::shared_ptr<DETECTION>> GetAssociatedDetections(std::shared_ptr<DETECTION> base, Aggressiveness level);
};