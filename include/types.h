#ifndef TYPES_H
#define TYPES_H

#include <chrono>

namespace regban {

using Time = std::chrono::time_point<std::chrono::system_clock>;
using Score = int;

}  // namespace regban

#endif
