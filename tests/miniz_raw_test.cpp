#include <cstdint>
#include <vector>
#include "../third_party/miniz/miniz_tinfl.h"

int main() {
    const std::vector<uint8_t> packed={203,72,205,201,201,87,40,207,47,202,73,201,24,101,142,50,71,153,163,76,114,153,0};
    std::vector<uint8_t> plain(1100);
    const size_t n=tinfl_decompress_mem_to_mem(plain.data(),plain.size(),packed.data(),packed.size(),
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if(n!=plain.size()) return 1;
    for(size_t i=0;i<plain.size();++i) if(plain[i]!="hello world"[i%11]) return 2;
    return 0;
}
