#ifndef OPENVPN_COMMON_HASH_H
#define OPENVPN_COMMON_HASH_H

#include <openvpn/common/types.hpp>

namespace openvpn {

  template <typename T>
  class HashInitialSeed
  {
  public:
    HashInitialSeed(std::size_t seed) : seed_(seed) {}

    std::size_t operator()(const T& obj) const
    {
      std::size_t seed = seed_;
      boost::hash_combine(seed, obj);
      return seed;
    }

  private:
    std::size_t seed_;
  };
}

#endif
