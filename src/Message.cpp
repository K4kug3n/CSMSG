#include <Message.hpp>

Message::Message(std::string content) :
	m_content(std::move(content)) { }

std::vector<uint8_t> Message::to_bytes() const {
	return std::vector<uint8_t>(m_content.begin(), m_content.end());
}

Message Message::FromBytes(const std::vector<uint8_t>& bytes) {
	return Message(std::string{ bytes.begin(), bytes.end() });
}

std::ostream& operator<<(std::ostream& stream, const Message& message) {
	stream << message.m_content;

	return stream;
}
