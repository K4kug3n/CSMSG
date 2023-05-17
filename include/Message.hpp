#ifndef CSMSG_MESSAGE_HPP
#define CSMSG_MESSAGE_HPP

#include <string>
#include <vector>
#include <ostream>

class Message {
public:
	Message() = delete;
	Message(std::string content);
	Message(const Message&) = default;
	Message(Message&&) = default;

	std::vector<uint8_t> to_bytes() const;

	static Message FromBytes(const std::vector<uint8_t>& bytes);

	Message& operator=(const Message&) = default;
	Message& operator=(Message&&) = default;

	friend std::ostream& operator<<(std::ostream& stream, const Message& message);
private:
	std::string m_content;
};




#endif