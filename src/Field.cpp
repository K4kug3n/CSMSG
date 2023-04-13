#include <Field.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <cassert>

namespace mp = boost::multiprecision;

mp::uint128_t multiply(uint64_t x, uint64_t y) {
	return mp::uint128_t{ x } * mp::uint128_t{ y };
}

uint64_t uint8_to_uint64(const std::array<uint8_t, 32>::const_iterator& it) {
	return uint64_t{ *it }
		| (uint64_t{ *(it + 1) } << 8)
		| (uint64_t{ *(it + 2) } << 16)
		| (uint64_t{ *(it + 3) } << 24)
		| (uint64_t{ *(it + 4) } << 32)
		| (uint64_t{ *(it + 5) } << 40)
		| (uint64_t{ *(it + 6) } << 48)
		| (uint64_t{ *(it + 7) } << 56);
}

FieldElement::FieldElement() :
	m_repr({ 0, 0, 0, 0, 0 }) { }

FieldElement::FieldElement(const std::array<uint8_t, 32>& bytes) {
	const uint64_t low_51_bit_mask = (uint64_t{ 1 } << 51) - 1;

	m_repr[0] = uint8_to_uint64(bytes.begin()) & low_51_bit_mask;
	m_repr[1] = (uint8_to_uint64(bytes.begin() + 6) >> 3) & low_51_bit_mask;
	m_repr[2] = (uint8_to_uint64(bytes.begin() + 12) >> 6) & low_51_bit_mask;
	m_repr[3] = (uint8_to_uint64(bytes.begin() + 19) >> 1) & low_51_bit_mask;
	m_repr[4] = (uint8_to_uint64(bytes.begin() + 24) >> 12) & low_51_bit_mask;
}

FieldElement::FieldElement(std::array<uint64_t, 5> parts) :
	m_repr(std::move(parts)) { }

FieldElement FieldElement::invert() const {
	FieldElement t19;
	FieldElement t3;
	std::pair<FieldElement&, FieldElement&>{ t19, t3 } = pow22501();

	const FieldElement t20 = t19.pow2k(5);
	const FieldElement t21 = t20 * t3;

	return t21;
}

FieldElement FieldElement::pow2k(uint32_t k) const {
	const uint64_t low_51_bit_mask = (uint64_t{ 1 } << 51) - 1;

	std::array<uint64_t, 5> a = m_repr;

	while (k != 0) {
		const uint64_t a3_19 = 19 * a[3];
		const uint64_t a4_19 = 19 * a[4];

		mp::uint128_t c_0 = multiply(a[0], a[0]) + 2 * (multiply(a[1], a4_19) + multiply(a[2], a3_19));
		mp::uint128_t c_1 = multiply(a[3], a3_19) + 2 * (multiply(a[0], a[1]) + multiply(a[2], a4_19));
		mp::uint128_t c_2 = multiply(a[1], a[1]) + 2 * (multiply(a[0], a[2]) + multiply(a[4], a3_19));
		mp::uint128_t c_3 = multiply(a[4], a4_19) + 2 * (multiply(a[0], a[3]) + multiply(a[1], a[2]));
		mp::uint128_t c_4 = multiply(a[2], a[2]) + 2 * (multiply(a[0], a[4]) + multiply(a[1], a[3]));

		assert(a[0] < (uint64_t{ 1 } << 54));
		assert(a[1] < (uint64_t{ 1 } << 54));
		assert(a[2] < (uint64_t{ 1 } << 54));
		assert(a[3] < (uint64_t{ 1 } << 54));
		assert(a[4] < (uint64_t{ 1 } << 54));

		c_1 += mp::uint128_t{ uint64_t{ c_0 >> 51 } };
		a[0] = uint64_t{ c_0 } & low_51_bit_mask;

		c_2 += mp::uint128_t{ uint64_t{ c_1 >> 51 } };
		a[1] = uint64_t{ c_1 } & low_51_bit_mask;

		c_3 += mp::uint128_t{ uint64_t{ c_2 >> 51 } };
		a[2] = uint64_t{ c_2 } & low_51_bit_mask;

		c_4 += mp::uint128_t{ uint64_t{ c_3 >> 51 } };
		a[3] = uint64_t{ c_3 } & low_51_bit_mask;

		uint64_t carry = uint64_t{ c_4 >> 51 };
		a[4] = uint64_t{ c_4 } & low_51_bit_mask;

		a[0] = a[0] + carry * 19;

		a[1] += a[0] >> 51;
		a[0] &= low_51_bit_mask;

		k = k - 1;
	}

	return FieldElement{ a };
}

std::pair<FieldElement, FieldElement> FieldElement::pow22501() const {
	const FieldElement t0 = square();
	const FieldElement t1 = t0.square().square();
	const FieldElement t2 = (*this) * t1;
	const FieldElement t3 = t0 * t2;
	const FieldElement t4 = t3.square();
	const FieldElement t5 = t2 * t4;
	const FieldElement t6 = t5.pow2k(5);
	const FieldElement t7 = t6 * t5;
	const FieldElement t8 = t7.pow2k(10);
	const FieldElement t9 = t8 * t7;
	const FieldElement t10 = t9.pow2k(20);
	const FieldElement t11 = t10 * t9;
	const FieldElement t12 = t11.pow2k(10);
	const FieldElement t13 = t12 * t7;
	const FieldElement t14 = t13.pow2k(50);
	const FieldElement t15 = t14 * t13;
	const FieldElement t16 = t15.pow2k(100);
	const FieldElement t17 = t16 * t15;
	const FieldElement t18 = t17.pow2k(50);
	const FieldElement t19 = t18 * t13;

	return std::pair<FieldElement, FieldElement>{ t19, t3 };
}

FieldElement FieldElement::square() const {
	return pow2k(1);
}

std::array<uint8_t, 32> FieldElement::to_bytes() const {
	std::array<uint64_t, 5> limbs = FieldElement::Reduce(m_repr).m_repr;

	uint64_t q = (limbs[0] + 19) >> 51;
	q = (limbs[1] + q) >> 51;
	q = (limbs[2] + q) >> 51;
	q = (limbs[3] + q) >> 51;
	q = (limbs[4] + q) >> 51;

	limbs[0] += 19 * q;

	const uint64_t low_51_bit_mask = (uint64_t{ 1 } << 51) - 1;
	limbs[1] += limbs[0] >> 51;
	limbs[0] = limbs[0] & low_51_bit_mask;
	limbs[2] += limbs[1] >> 51;
	limbs[1] = limbs[1] & low_51_bit_mask;
	limbs[3] += limbs[2] >> 51;
	limbs[2] = limbs[2] & low_51_bit_mask;
	limbs[4] += limbs[3] >> 51;
	limbs[3] = limbs[3] & low_51_bit_mask;
	limbs[4] = limbs[4] & low_51_bit_mask;

	std::array<uint8_t, 32> s;
	s[0] = limbs[0];
	s[1] = uint64_t{ limbs[0] >> 8 };
	s[2] = uint64_t{ limbs[0] >> 16 };
	s[3] = uint64_t{ limbs[0] >> 24 };
	s[4] = uint64_t{ limbs[0] >> 32 };
	s[5] = uint64_t{ limbs[0] >> 40 };
	s[6] = uint64_t{ (limbs[0] >> 48) | (limbs[1] << 3) };
	s[7] = uint64_t{ limbs[1] >> 5 };
	s[8] = uint64_t{ limbs[1] >> 13 };
	s[9] = uint64_t{ limbs[1] >> 21 };
	s[10] = uint64_t{ limbs[1] >> 29 };
	s[11] = uint64_t{ limbs[1] >> 37 };
	s[12] = uint64_t{ (limbs[1] >> 45) | (limbs[2] << 6) };
	s[13] = uint64_t{ limbs[2] >> 2 };
	s[14] = uint64_t{ limbs[2] >> 10 };
	s[15] = uint64_t{ limbs[2] >> 18 };
	s[16] = uint64_t{ limbs[2] >> 26 };
	s[17] = uint64_t{ limbs[2] >> 34 };
	s[18] = uint64_t{ limbs[2] >> 42 };
	s[19] = uint64_t{ (limbs[2] >> 50) | (limbs[3] << 1) };
	s[20] = uint64_t{ limbs[3] >> 7 };
	s[21] = uint64_t{ limbs[3] >> 15 };
	s[22] = uint64_t{ limbs[3] >> 23 };
	s[23] = uint64_t{ limbs[3] >> 31 };
	s[24] = uint64_t{ limbs[3] >> 39 };
	s[25] = uint64_t{ (limbs[3] >> 47) | (limbs[4] << 4) };
	s[26] = uint64_t{ limbs[4] >> 4 };
	s[27] = uint64_t{ limbs[4] >> 12 };
	s[28] = uint64_t{ limbs[4] >> 20 };
	s[29] = uint64_t{ limbs[4] >> 28 };
	s[30] = uint64_t{ limbs[4] >> 36 };
	s[31] = uint64_t{ limbs[4] >> 44 };

	assert((s[31] & 0b10000000) == 0);

	return s;
}

FieldElement FieldElement::One() {
	return FieldElement(std::array<uint64_t, 5>{ 1, 0, 0, 0, 0 });
}

FieldElement FieldElement::Reduce(std::array<uint64_t, 5> parts) {
	const uint64_t low_51_bit_mask = (uint64_t{ 1 } << 51) - 1;

	const uint64_t c_0 = parts[0] >> 51;
	const uint64_t c_1 = parts[1] >> 51;
	const uint64_t c_2 = parts[2] >> 51;
	const uint64_t c_3 = parts[3] >> 51;
	const uint64_t c_4 = parts[4] >> 51;

	parts[0] &= low_51_bit_mask;
	parts[1] &= low_51_bit_mask;
	parts[2] &= low_51_bit_mask;
	parts[3] &= low_51_bit_mask;
	parts[4] &= low_51_bit_mask;

	parts[0] += c_4 * 19;
	parts[1] += c_0;
	parts[2] += c_1;
	parts[3] += c_2;
	parts[4] += c_3;

	return FieldElement{ parts };
}

FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs) {
	return FieldElement::Reduce({
		(lhs.m_repr[0] + 36028797018963664) - rhs.m_repr[0],
		(lhs.m_repr[1] + 36028797018963952) - rhs.m_repr[1],
		(lhs.m_repr[2] + 36028797018963952) - rhs.m_repr[2],
		(lhs.m_repr[3] + 36028797018963952) - rhs.m_repr[3],
		(lhs.m_repr[4] + 36028797018963952) - rhs.m_repr[4],
	});
}

FieldElement operator-(const FieldElement& rhs) {
	return FieldElement::Reduce({
		36028797018963664 - rhs.m_repr[0],
		36028797018963952 - rhs.m_repr[1],
		36028797018963952 - rhs.m_repr[2],
		36028797018963952 - rhs.m_repr[3],
		36028797018963952 - rhs.m_repr[4]
	});
}

FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs) {
	std::array<uint64_t, 5> out = lhs.m_repr;
	for (size_t i = 0; i < out.size(); ++i) {
		out[i] += rhs.m_repr[i];
	}

	return FieldElement{ out };
}

FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs) {
	const uint64_t low_51_bit_mask = (uint64_t{ 1 } << 51) - 1;

	const uint64_t b1_19 = rhs.m_repr[1] * 19;
	const uint64_t b2_19 = rhs.m_repr[2] * 19;
	const uint64_t b3_19 = rhs.m_repr[3] * 19;
	const uint64_t b4_19 = rhs.m_repr[4] * 19;

	mp::uint128_t c_0 = multiply(lhs.m_repr[0], rhs.m_repr[0]) + multiply(lhs.m_repr[4], b1_19) + multiply(lhs.m_repr[3], b2_19) + multiply(lhs.m_repr[2], b3_19) + multiply(lhs.m_repr[1], b4_19);
	mp::uint128_t c_1 = multiply(lhs.m_repr[1], rhs.m_repr[0]) + multiply(lhs.m_repr[0], rhs.m_repr[1]) + multiply(lhs.m_repr[4], b2_19) + multiply(lhs.m_repr[3], b3_19) + multiply(lhs.m_repr[2], b4_19);
	mp::uint128_t c_2 = multiply(lhs.m_repr[2], rhs.m_repr[0]) + multiply(lhs.m_repr[1], rhs.m_repr[1]) + multiply(lhs.m_repr[0], rhs.m_repr[2]) + multiply(lhs.m_repr[4], b3_19) + multiply(lhs.m_repr[3], b4_19);
	mp::uint128_t c_3 = multiply(lhs.m_repr[3], rhs.m_repr[0]) + multiply(lhs.m_repr[2], rhs.m_repr[1]) + multiply(lhs.m_repr[1], rhs.m_repr[2]) + multiply(lhs.m_repr[0], rhs.m_repr[3]) + multiply(lhs.m_repr[4], b4_19);
	mp::uint128_t c_4 = multiply(lhs.m_repr[4], rhs.m_repr[0]) + multiply(lhs.m_repr[3], rhs.m_repr[1]) + multiply(lhs.m_repr[2], rhs.m_repr[2]) + multiply(lhs.m_repr[1], rhs.m_repr[3]) + multiply(lhs.m_repr[0], rhs.m_repr[4]);

	std::array<uint64_t, 5> out = { 0, 0, 0, 0, 0 };

	c_1 += mp::uint128_t{ uint64_t{ c_0 >> 51 } };
	out[0] = uint64_t{ c_0 } &low_51_bit_mask;

	c_2 += mp::uint128_t{ uint64_t{ c_1 >> 51 } };
	out[1] = uint64_t{ c_1 } &low_51_bit_mask;

	c_3 += mp::uint128_t{ uint64_t{ c_2 >> 51 } };
	out[2] = uint64_t{ c_2 } & low_51_bit_mask;

	c_4 += mp::uint128_t{ uint64_t{ c_3 >> 51 } };
	out[3] = uint64_t{ c_3 } & low_51_bit_mask;

	uint64_t carry = uint64_t{ c_4 >> 51 };
	out[4] = uint64_t{ c_4 } & low_51_bit_mask;

	out[0] = out[0] + carry * 19;

	out[1] += out[0] >> 51;
	out[0] &= low_51_bit_mask;

	return FieldElement{ out };
}
