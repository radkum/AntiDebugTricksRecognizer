#pragma once

#define ASSERT(x)			if((x) == false) return -2;
#define ASSERT_BOOL(x)		if((x) == false) return false;
#define ASSERT_BREAK(x)		if((x) == false) break;