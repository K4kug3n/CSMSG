#include <Utility.hpp>

template<typename T1, typename T2>
inline T1 pos_mod(const T1& x, const T2& p) {
	return ((x % p) + p) % p;
}
