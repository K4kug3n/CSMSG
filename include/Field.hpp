#ifndef CSMSG_FIELD_HPP
#define CSMSG_FIELD_HPP

#include <utility>
#include <array>

class FieldElement {
public:
	FieldElement();
	FieldElement(const std::array<uint8_t, 32>& bytes);
	FieldElement(std::array<uint64_t, 5> parts);

	FieldElement invert() const;
	FieldElement negative() const;
	FieldElement pow2k(uint32_t k) const;
	std::pair<FieldElement, FieldElement> pow22501() const;
	FieldElement square() const;
	std::array<uint8_t, 32> to_bytes() const;

	friend FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs);
	friend FieldElement operator-(const FieldElement& rhs);
	friend FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs);
	friend FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs);

	static FieldElement One();
	static FieldElement Reduce(std::array<uint64_t, 5> parts);
private:
	std::array<uint64_t, 5> m_repr;
};

FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs);
FieldElement operator-(const FieldElement& rhs);
FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs);
FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs);

#endif