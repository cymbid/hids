//
//  Server.hpp
//  raserver
//
//  Created by orchid on 2018. 9. 3..
//

#ifndef Server_hpp
#define Server_hpp

// #include "RestApi.hpp"
#include "nlohmann/json.hpp"
// #include "server_https.hpp"

#include <functional>
#include <memory>
#include <thread>
#include <unordered_map>

// using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
// using HttpsServer = SimpleWeb::Server<SimpleWeb::HTTPS>;

// class RestApi;
class HttpServerInfo;
class Server
{
private:
    std::unique_ptr<HttpServerInfo> httpServerInfo;

    nlohmann::json svrConf;
    bool useSSL;

    std::thread serverThread;

public:
    Server();
    ~Server();

    bool init(nlohmann::json &conf);

    bool initResource();

    bool start();
    bool join();
    bool stop();

    std::unordered_map<std::string, std::function<std::string(const nlohmann::json &)> > restApiMap;
};

#endif /* Server_hpp */
