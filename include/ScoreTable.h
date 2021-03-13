#ifndef SCORETABLE_H
#define SCORETABLE_H

#include <vector>

#include "types.h"

namespace regban {

class ScoreTable {
  public:
    struct Element {
        Score lower_bound;
        unsigned int bantime;
        Score add_score;
    };

  private:
    std::vector<Element> table;

  public:
    explicit ScoreTable(Score base_add_score = 0) { table.emplace_back<Element>({0, 0, base_add_score}); }

    void add(Element e) {
        auto it = std::cbegin(table);
        for (; it != std::cend(table); ++it) {
            if (it->lower_bound > e.lower_bound) {
                break;
            }
        }
        table.emplace(it, std::move(e));
    }

    const Element& lookup(Score score) const {
        auto it = std::cbegin(table);
        for (; it + 1 != std::cend(table); ++it) {
            if ((it + 1)->lower_bound > score) {
                break;
            }
        }
        return *it;
    }
};

}  // namespace regban

#endif
