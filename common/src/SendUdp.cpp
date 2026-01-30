#include "SendUdp.hpp"

#include "asio.hpp"

namespace AC {
namespace AIds {

class AsioInfoCli
{
public:
    AsioInfoCli()
        : socket(context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0))
    {
    }
    ~AsioInfoCli()
    {
        LOG_INF("AsioInfoCli destructor");
    }
    asio::io_context context;
    asio::ip::udp::socket socket;
    asio::ip::udp::resolver::results_type endpoints;
};

SendUdp::SendUdp(std::string ip, uint16_t port)
    : ip(ip)
    , port(port)
    , asioInfo(new AsioInfoCli())
{
}

SendUdp::~SendUdp()
{
    asioInfo->socket.close();
}

void SendUdp::connect()
{
    LOG_INF("connect to {}:{}", ip, port);
    asio::ip::udp::resolver resolver(asioInfo->context);
    asioInfo->endpoints = resolver.resolve(ip, std::to_string(port));
    // asio::connect(asioInfo->socket, endpoints);
}

void SendUdp::send(ByteData& data)
{
    asioInfo->socket.send_to(asio::buffer(data.data(), data.size()), *asioInfo->endpoints);
}

}  // namespace AIds
}  // namespace AC
