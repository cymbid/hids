#pragma once

#include "Log.hpp"
#include "Util.hpp"

#include <memory>
#include <thread>

namespace AC {
namespace AIds {

class AsioInfoCli;
class SendUdp
{
private:
    std::string ip;
    uint16_t port;

    std::unique_ptr<AsioInfoCli> asioInfo;
    std::thread threadCli;
    // std::vector<std::shared_ptr<Session> > sessions;

public:
    SendUdp(std::string ip, uint16_t port);
    ~SendUdp();

    void connect();

    void send(ByteData& data);
};

}  // namespace AIds
}  // namespace AC