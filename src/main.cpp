#include <signal.h>

#include <array>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include "RegBan.h"
#include "settingsnode.h"
#include "settingsnode/inner.h"
#include "settingsnode/yaml.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"
#include "version.h"

regban::RegBan* rb = nullptr;

static int run(const settings::SettingsNode& settings, bool dry_run) {
    std::shared_ptr<spdlog::logger> logger;
    if (settings.has("log")) {
        const auto& logsettings = settings["log"];
        if (logsettings.has("level")) {
            spdlog::set_level(spdlog::level::from_str(logsettings["level"].as<std::string>()));
        }
        if (logsettings.has("pattern")) {
            spdlog::set_pattern(logsettings["pattern"].as<std::string>());
        }
        if (logsettings.has("filename")) {
            logger = spdlog::basic_logger_st("main", logsettings["filename"].as<std::string>());
        }
    }
    if (!logger) {
        logger = spdlog::stdout_color_st("main");
    }
    spdlog::set_default_logger(logger);

    try {
        regban::RegBan r(settings, dry_run);
        rb = &r;
        const auto& statefilename = settings["statefile"].as<std::string>("");
        if (!statefilename.empty()) {
            std::ifstream statefile(statefilename);
            if (statefile) {
                try {
                    r.read_state(settings::SettingsNode(std::make_unique<settings::YAML>(statefile)));
                } catch (const std::exception& ex) {
                    logger->error("Could not parse state file: {}", ex.what());
                }
            } else {
                logger->error("Cannot open state file {}", statefilename);
            }
        }
        r.run();
        if (!statefilename.empty()) {
            r.write_state(statefilename);
        }
        return 0;
    } catch (const std::exception& ex) {
        logger->critical(ex.what());
        return 255;
    }
}

void sig_handler(int sig) {
    (void)sig;
    if (rb != nullptr) {
        rb->stop();
    }
}

static void print_usage(const char* program_name) {
    std::cerr << "RegBan - Ban IPs based on log RegExp matches\n"
                 "Version: "
              << regban::version
              << "\n\n"
                 "Author: Sven Willner <sven.willner@gmail.com>\n"
                 "\n"
                 "Usage:   "
              << program_name
              << " (<option> | <settingsfile>)\n"
                 "Options:\n"
              << (regban::has_diff ? "      --diff     Print git diff output from compilation\n" : "") << "  -d, --dry-run  Dry run\n"
              << "  -h, --help     Print this help text\n"
                 "  -v, --version  Print version"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    std::string arg = argv[1];
    bool dry_run = false;
    if (arg.length() > 1 && arg[0] == '-') {
        if (arg == "--version" || arg == "-v") {
            std::cout << regban::version << std::endl;
            return 0;
        }
        if (regban::has_diff && arg == "--diff") {
            std::cout << regban::git_diff << std::flush;
            return 0;
        }
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "--dry-run" || arg == "-d") {
            dry_run = true;
            if (argc != 3) {
                print_usage(argv[0]);
                return 1;
            }
            arg = argv[2];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    try {
        if (arg == "-") {
            std::cin >> std::noskipws;
            return run(settings::SettingsNode(std::make_unique<settings::YAML>(std::cin)), dry_run);
        }
        std::ifstream settings_file(arg);
        if (!settings_file) {
            throw std::runtime_error("Cannot open " + arg);
        }
        return run(settings::SettingsNode(std::make_unique<settings::YAML>(settings_file)), dry_run);
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 255;
    }
}
