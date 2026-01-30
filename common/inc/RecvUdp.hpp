#pragma once

#include "Log.hpp"
#include "Util.hpp"

#include <functional>
#include <memory>
#include <thread>

namespace AC {
namespace AIds {

class AsioInfoSvr;
class RecvUdp
{
private:
    std::unique_ptr<AsioInfoSvr> asioInfo;
    // std::thread threadSvr;
    std::function<void(const std::string&, uint16_t, std::shared_ptr<ByteData>)> recvCallback;

    void waitRecv();

    virtual void recvCallbackFunc(const std::string& remoteIp, uint16_t remotePort, std::shared_ptr<ByteData> data);

public:
    RecvUdp(uint16_t port);
    ~RecvUdp();

    void setRecv(std::function<void(const std::string&, uint16_t, std::shared_ptr<ByteData>)> recvCallback);
    void start();

    void close();
};

}  // namespace AIds
}  // namespace AC