#include "RecvUdp.hpp"

#include "asio.hpp"

namespace AC {
namespace AIds {

class AsioInfoSvr
{
public:
    AsioInfoSvr(uint16_t port)
        : socket_(context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port))
    {
    }
    ~AsioInfoSvr()
    {
        LOG_INF("AsioInfoSvr destructor");
    }
    asio::io_context context;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint remoteEndpoint;
    uint8_t recvBuffer[4096];
};

RecvUdp::RecvUdp(uint16_t port)
    : asioInfo(new AsioInfoSvr(port))
{
    recvCallback = [this](const std::string& remoteIp, uint16_t remotePort, std::shared_ptr<ByteData> data) {
        this->recvCallbackFunc(remoteIp, remotePort, data);
    };
}

RecvUdp::~RecvUdp()
{
}

void RecvUdp::setRecv(std::function<void(const std::string&, uint16_t, std::shared_ptr<ByteData>)> recvCallback)
{
    this->recvCallback = recvCallback;
}

void RecvUdp::start()
{
    waitRecv();

    asioInfo->context.run();
}

void RecvUdp::close()
{
    asioInfo->context.stop();
}

void RecvUdp::waitRecv()
{
    asioInfo->socket_.async_receive_from(asio::buffer(asioInfo->recvBuffer), asioInfo->remoteEndpoint,
                                         [this](std::error_code ec, std::size_t bytes_recvd) {
                                             if (!ec && bytes_recvd > 0)
                                             {
                                                 std::string remoteIp = asioInfo->remoteEndpoint.address().to_string();
                                                 uint16_t remotePort = asioInfo->remoteEndpoint.port();
                                                 auto data = std::make_shared<ByteData>(
                                                     asioInfo->recvBuffer, asioInfo->recvBuffer + bytes_recvd);
                                                 recvCallback(remoteIp, remotePort, data);
                                             }
                                             else
                                             {
                                                 LOG_ERR("recv error: {}", ec.message());
                                             }

                                             waitRecv();
                                         });
}

void RecvUdp::recvCallbackFunc(const std::string& remoteIp, uint16_t remotePort, std::shared_ptr<ByteData> data)
{
    LOG_DBG("recv from {}:{}", remoteIp, remotePort);
    LOG_DBG("data: {}", *data);
}

}  // namespace AIds
}  // namespace AC
