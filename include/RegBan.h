#ifndef REGBAN_H
#define REGBAN_H

#include <sys/select.h>
#include <sys/wait.h>

#include <array>
#include <cstdio>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

#include "IPTable.h"
#include "IPvX.h"
#include "ScoreTable.h"
#include "SystemBanSet.h"
#include "csv-parser.h"
#include "settingsnode.h"
#include "spdlog/spdlog.h"
#include "types.h"

// include last
#include "spdlog/fmt/ostr.h"

namespace regban {

constexpr auto BUFFER_SIZE = 1000;
constexpr auto IP_REGEXP = "([0-9a-f:\\.]+)";

static std::string fill_template(const std::string& in) {
    constexpr const char* beg_mark = "{{";
    constexpr const char* end_mark = "}}";
    std::ostringstream ss;
    std::size_t pos = 0;
    while (true) {
        std::size_t start = in.find(beg_mark, pos);
        std::size_t stop = in.find(end_mark, start);
        if (stop == std::string::npos) {
            break;
        }
        ss.write(&*in.begin() + pos, start - pos);
        start += std::strlen(beg_mark);
        std::string key = in.substr(start, stop - start);
        if (key == "ip") {
            ss << IP_REGEXP;
        } else {
            throw std::runtime_error("Unknown template '" + key + "'");
        }
        pos = stop + std::strlen(end_mark);
    }
    ss << in.substr(pos, std::string::npos);
    return ss.str();
}

class RegBan {
  private:
    struct BanData {
        Time last_scoretime;
        Time last_bantime;
        Score score;
    };
    struct Pattern {
        std::regex pattern;
        Score score;
    };
    struct Process {
        std::string command;
        std::string name;
        int fd;
        pid_t pid;
        FILE* stream = nullptr;
        std::array<char, BUFFER_SIZE> buf;
        int bufcount = 0;
        std::vector<Pattern> patterns;

        Process() = default;
        Process(const Process&) = delete;
        Process& operator=(const Process&) = delete;
        Process(Process&&) = default;
        Process& operator=(Process&&) = default;

        void open_process() {
            close_process();

            int p[2];
            if (pipe2(p, O_NONBLOCK) < 0) {
                throw std::runtime_error("Could not create pipe: " + std::string(std::strerror(errno)));
            }
            pid = fork();
            if (pid < 0) {
                throw std::runtime_error("Could not fork: " + std::string(std::strerror(errno)));
            }
            if (pid == 0) {
                close(p[0]);
                if (dup2(p[1], STDOUT_FILENO) < 0) {
                    throw std::runtime_error("Could not redirect stdout: " + std::string(std::strerror(errno)));
                }
                close(p[1]);
                const char* args[] = {"/bin/sh", "-c", command.c_str(), nullptr};
                execv(args[0], const_cast<char* const*>(args));
                throw std::runtime_error("Could not run \"/bin/sh -c '" + command + "'\": " + std::strerror(errno));
            }
            close(p[1]);
            fd = p[0];
            stream = fdopen(fd, "r");
            if (stream == nullptr) {
                throw std::runtime_error("Could not open stream to '" + command + "': " + std::strerror(errno));
            }
        }
        void close_process() {
            if (stream != nullptr) {
                kill(pid, SIGTERM);
                stream = nullptr;
            }
        }
        ~Process() { close_process(); }
    };

    IPRangeTable<Score> rangetable;
    IPTable<BanData> iptable;
    Score score_decay;
    ScoreTable scoretable;
    SystemBanSet banset;
    unsigned int cleanup_interval;
    Time last_cleanup;
    unsigned int score_decay_interval;
    unsigned int restart_usleep;
    bool dry_run;
    int selfpipe[2];  // for self-pipe trick to cancel select() call
    std::shared_ptr<spdlog::logger> logger;
    std::vector<Process> processes;
    bool ipv4_enabled;
    bool ipv6_enabled;

  public:
    RegBan(const settings::SettingsNode& settings, bool dry_run_p) : dry_run(dry_run_p) {
        logger = spdlog::default_logger()->clone("RegBan");

        cleanup_interval = settings["cleanupinterval"].as<unsigned int>();
        restart_usleep = settings["restartusleep"].as<unsigned int>(0);

        const auto& nftsettings = settings["nft"];
        ipv4_enabled = nftsettings.has("ipv4set");
        ipv6_enabled = nftsettings.has("ipv6set");
        if (!dry_run) {
            banset.initialize(nftsettings["type"].as<std::string>(), nftsettings["table"].as<std::string>(), nftsettings["ipv4set"].as<std::string>(""),
                              nftsettings["ipv6set"].as<std::string>(""));
        }

        for (const auto& processessettings : settings["processes"].as_sequence()) {
            Process& process = *processes.emplace(std::end(processes));
            process.command = processessettings["command"].as<std::string>();
            process.name = processessettings["name"].as<std::string>();
            for (const auto& patternsettings : processessettings["patterns"].as_sequence()) {
                const auto p = fill_template(patternsettings["pattern"].as<std::string>());
                const auto regex = std::regex(p, std::regex::optimize);
                if (regex.mark_count() != 1) {
                    throw std::runtime_error("Regexp needs to have exactly one subgroup for " + p);
                }
                process.patterns.emplace_back(Pattern{regex, patternsettings["score"].as<Score>()});
            }
            process.open_process();
        }

        for (const auto& rangetablesettings : settings["rangetables"].as_sequence()) {
            if (rangetablesettings.has("filename")) {
                const auto& filename = rangetablesettings["filename"].as<std::string>();
                std::ifstream file(filename);
                if (!file) {
                    throw std::runtime_error("Could not open '" + filename + "'");
                }
                try {
                    csv::Parser parser(file);
                    do {
                        const auto c = parser.read<std::string, unsigned char, Score>();
                        rangetable.find_or_insert(IPvX::parse(std::get<0>(c).c_str()), std::get<1>(c)).second = std::get<2>(c);
                    } while (parser.next_row());
                } catch (const csv::parser_exception& ex) {
                    throw std::runtime_error(ex.format());
                }
            } else {
                rangetable.find_or_insert(IPvX::parse(rangetablesettings["ip"].as<std::string>().c_str()), rangetablesettings["cidr"].as<unsigned>()).second =
                    rangetablesettings["score"].as<Score>();
            }
        }

        const auto& scoressettings = settings["scores"];
        const auto& scoredecaysettings = scoressettings["decay"];
        score_decay = scoredecaysettings["amount"].as<Score>();
        score_decay_interval = scoredecaysettings["per"].as<unsigned int>();

        for (const auto& scoretableentry : scoressettings["table"].as_map()) {
            scoretable.add(ScoreTable::Element{
                std::stoi(scoretableentry.first),
                scoretableentry.second["bantime"].as<unsigned int>(),
                scoretableentry.second["score"].as<Score>(),
            });
        }
    }

    ~RegBan() { stop(); }

    void adjust_ip_score(BanData& bandata, Time now) {
        const auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - bandata.last_scoretime).count() * score_decay / score_decay_interval;
        if (bandata.score <= diff) {
            bandata.score = 0;
        } else {
            bandata.score -= diff;
        }
        bandata.last_scoretime = now;
    }

    void cleanup(Time now) {
        std::vector<IPvX> to_remove;
        for (auto e : iptable) {
            const auto ip = e.first;
            auto& bandata = e.second;
            adjust_ip_score(bandata, now);
            if (bandata.score <= 0) {
                to_remove.emplace_back(ip);
            }
        }
        for (const auto ip : to_remove) {
            iptable.remove(ip);
        }
    }

    void handle_ip(IPvX ip, Time now, Score add_score, const std::string& process_name) {
        if (!ipv4_enabled && !ip.is_ipv6()) {
            logger->debug("Match in {} ({} +{} - -- ipv4 disabled)", process_name, IPvX::Formatter(ip), add_score);
            return;
        }
        if (!ipv6_enabled && ip.is_ipv6()) {
            logger->debug("Match in {} ({} +{} - -- ipv6 disabled)", process_name, IPvX::Formatter(ip), add_score);
            return;
        }
        const auto rangelookup = rangetable.find_range_for(ip);
        if (rangelookup.second != nullptr) {
            const auto rangescore = *rangelookup.second;
            if (rangescore <= 0) {  // ip is always allowed
                logger->info("Match in {} ({} +{} 0 -- always allowed)", process_name, IPvX::Formatter(ip), add_score);
                return;
            }
            add_score += rangescore;
        }
        auto iplookup = iptable.find_or_insert(ip);
        const bool found = iplookup.first;
        auto& bandata = iplookup.second;
        if (found) {
            adjust_ip_score(bandata, now);
        }
        bandata.last_scoretime = now;
        bandata.score += add_score;
        const auto& tabledata = scoretable.lookup(bandata.score);
        bandata.score += tabledata.add_score;
        if (tabledata.bantime > 0) {
            logger->info("Match in {} ({} +{} {} -- banning for {}s)", process_name, IPvX::Formatter(ip), add_score, bandata.score, tabledata.bantime);
            if (!dry_run) {
                banset.add_ip(ip, tabledata.bantime);
                banset.commit_batch();
            }
            bandata.last_bantime = now;
        } else {
            logger->info("Match in {} ({} +{} {})", process_name, IPvX::Formatter(ip), add_score, bandata.score);
        }
    }

    void check_process(Process& process, Time now) {
        const auto nread = std::fread(&process.buf[process.bufcount], sizeof(process.buf[0]), process.buf.size() - process.bufcount - 1, process.stream);
        if (nread == 0) {
            int stat;
            waitpid(process.pid, &stat, 0);
            if (WIFEXITED(stat) | WIFSIGNALED(stat)) {
                logger->debug("Command '{}' exited with rc {}", process.command, WEXITSTATUS(stat));
                if (WEXITSTATUS(stat) != 0) {
                    throw std::runtime_error("Command '" + process.command + "' failed");
                }
                logger->info("Restarting '{}'", process.command);
                if (restart_usleep > 0) {
                    usleep(restart_usleep);
                }
                process.open_process();
            }
        }
        logger->debug("Read {} bytes", nread);
        process.bufcount += nread;
        process.buf[process.bufcount] = '\0';
        auto* begin = &process.buf[0];
        auto* end = begin;
        while ((end = std::strchr(begin, '\n')) != nullptr) {
            *end = '\0';
            if (end > begin && *(end - 1) == '\r') {
                *(end - 1) = '\0';
            }
            for (const auto& pattern : process.patterns) {
                std::cmatch match;
                if (std::regex_match(begin, match, pattern.pattern)) {
                    const auto& submatch = match[1];
                    logger->debug("Found match for line '{}' with ip {}", begin, submatch.str());
                    const auto ip = IPvX::parse(submatch.str().c_str());
                    if (ip > 0) {
                        handle_ip(ip, now, pattern.score, process.name);
                    } else {
                        logger->error("Could not parse ip from '{}'", submatch.str());
                    }
                }
            }
            begin = end + 1;
        }
        std::memmove(&process.buf[0], begin, process.bufcount + &process.buf[0] - begin);
        process.bufcount -= begin - &process.buf[0];
    }

    void run() {
        pipe(selfpipe);
        last_cleanup = std::chrono::system_clock::now();
        fd_set fds;
        while (processes.size() > 0) {
            FD_ZERO(&fds);
            auto nfds = selfpipe[0];
            FD_SET(selfpipe[0], &fds);
            for (const auto& process : processes) {
                FD_SET(process.fd, &fds);
                if (process.fd > nfds) {
                    nfds = process.fd;
                }
            }
            logger->debug("Waiting for new lines from {} processes...", processes.size());
            const auto n = select(nfds + 1, &fds, nullptr, nullptr, nullptr);
            const auto now = std::chrono::system_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup).count() > cleanup_interval) {
                cleanup(now);
            }
            if (n <= 0) {
                if (errno != EINTR) {
                    throw std::runtime_error(std::string("select() failed: ") + std::strerror(errno));
                }
                break;
            }
            for (auto& process : processes) {
                if (FD_ISSET(process.fd, &fds) != 0) {
                    check_process(process, now);
                }
            }
        }
    }

    void read_state(const settings::SettingsNode& state) {
        for (const auto& p : state.as_map()) {
            auto iplookup = iptable.find_or_insert(IPvX::parse(p.first.c_str()));
            iplookup.second.last_scoretime = std::chrono::system_clock::from_time_t(p.second["last_scoretime"].as<unsigned long>());
            iplookup.second.score = p.second["score"].as<Score>();
        }
    }

    void write_state(const std::string& filename) {
        std::ofstream o(filename);
        for (const auto& p : iptable) {
            o << '"' << p.first << "\":\n  last_scoretime: " << std::chrono::system_clock::to_time_t(p.second.last_scoretime) << "\n  score: " << p.second.score
              << "\n";
        }
    }

    void stop() {
        processes.clear();
        write(selfpipe[1], "\0", 1);
    }
};

}  // namespace regban

#endif
