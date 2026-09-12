#include <algorithm>
#include <array>
#include <cstdint>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
static uint16_t le16(const uint8_t* p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
static uint32_t le32(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }
static uint64_t le64(const uint8_t* p) { return uint64_t(le32(p)) | uint64_t(le32(p + 4)) << 32; }
static void put32(uint8_t* p,uint32_t v) { for(int i=0;i<4;++i) p[i]=uint8_t(v>>(8*i)); }
static void put64(uint8_t* p,uint64_t v) { for(int i=0;i<8;++i) p[i]=uint8_t(v>>(8*i)); }
static uint32_t rol1(uint32_t v) { return (v << 1) | (v >> 31); }
static uint32_t crc32(const uint8_t* p,size_t n) {
    uint32_t c=0xffffffffU; while(n--) { c^=*p++; for(int i=0;i<8;++i) c=(c>>1)^(0xedb88320U&uint32_t(0-int(c&1))); } return ~c;
}

static uint32_t tbi_hash(const uint8_t* p, size_t n) {
    uint32_t h = 0; size_t off = 0;
    while (n - off >= 4) { uint32_t w = le32(p + off); h = w ^ rol1(w + h); off += 4; }
    if (off != n) { uint32_t w = 0; for (size_t i = 0; off + i < n; ++i) w |= uint32_t(p[off + i]) << (8 * i); h = w ^ rol1(w + h); }
    return h;
}
static void read_exact(std::istream& in, void* dst, size_t n, const char* what) {
    in.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
    if (static_cast<size_t>(in.gcount()) != n) throw std::runtime_error(std::string("truncated ") + what);
}
struct Record { uint32_t type{}, size{}, check{}; std::vector<uint8_t> data; };
static Record read_record(std::istream& in) {
    std::array<uint8_t, 12> h{}; read_exact(in, h.data(), h.size(), "record header");
    Record r{le32(h.data()), le32(h.data()+4), le32(h.data()+8), {}};
    if (r.type == 0xffffffffU) return r;
    if (r.size > 64U*1024U*1024U) throw std::runtime_error("implausible metadata record size");
    r.data.resize(r.size); if (r.size) read_exact(in, r.data.data(), r.size, "record payload");
    if (r.check != ((r.type+r.size)^tbi_hash(r.data.data(),r.data.size()))) throw std::runtime_error("metadata checksum mismatch");
    return r;
}

// Exact Image for Linux routine at 0x81A3230 (compression options 14/15).
static std::vector<uint8_t> decode_lz(const std::vector<uint8_t>& src, size_t out_size) {
    std::vector<uint8_t> out; out.reserve(out_size); size_t ip=0;
    auto byte=[&](){ if(ip>=src.size()) throw std::runtime_error("truncated compressed block"); return src[ip++]; };
    auto word=[&](){ uint16_t a=byte(),b=byte(); return uint16_t(a|(b<<8)); };
    while(out.size()<out_size) {
        uint8_t t=byte();
        if(t&0x80) {
            size_t count=((t&0x20)?word():(t&0x1f))+4U;
            size_t distance=((t&0x40)?word():byte())+1U;
            if(distance>out.size()||count>out_size-out.size()) throw std::runtime_error("invalid LZ back-reference");
            for(size_t i=0;i<count;++i) out.push_back(out[out.size()-distance]);
        } else {
            size_t count=(t&0x40)?(((t&0x20)?word():byte())+65U):(size_t(t)+1U);
            if(count>src.size()-ip||count>out_size-out.size()) throw std::runtime_error("invalid LZ literal");
            out.insert(out.end(),src.begin()+static_cast<std::ptrdiff_t>(ip),src.begin()+static_cast<std::ptrdiff_t>(ip+count)); ip+=count;
        }
    }
    return out;
}

// Legacy bit-oriented codec at imagel 0x820E5A0/0x820E5E0.
static std::vector<uint8_t> decode_legacy(const std::vector<uint8_t>& src,size_t out_size) {
    std::vector<uint8_t> out; out.reserve(out_size); size_t bit=3;
    auto bits=[&](unsigned n)->uint32_t { if(n>24||bit+n>src.size()*8) throw std::runtime_error("truncated legacy stream"); uint32_t v=0; for(unsigned i=0;i<n;++i) v|=uint32_t((src[(bit+i)/8]>>((bit+i)%8))&1)<<i; bit+=n; return v; };
    auto unary=[&]()->unsigned { unsigned n=0; while(bits(1)==0) { if(++n>15) throw std::runtime_error("invalid legacy prefix"); } return n; };
    while(out.size()<out_size) {
        if(bits(1)==0) { out.push_back(uint8_t(bits(8))); continue; }
        unsigned k=unary(); size_t length=(size_t(1)<<k)+bits(k)+1;
        size_t distance;
        if(length==2) distance=bits(8);
        else { unsigned d=unary(); distance=((size_t(bits(d))+((size_t(1)<<d)-1))<<8)|bits(8); }
        if(!distance||distance>out.size()||length>out_size-out.size()) throw std::runtime_error("invalid legacy back-reference");
        for(size_t i=0;i<length;++i) out.push_back(out[out.size()-distance]);
    }
    return out;
}

// Raw RFC 1951 DEFLATE used when the IMG2 header's compression flag is 1.
static std::vector<uint8_t> decode_deflate(const std::vector<uint8_t>& src,size_t out_size) {
    struct Bits {
        const std::vector<uint8_t>& s; size_t p=0;
        uint32_t get(unsigned n) { if(n>24||p+n>s.size()*8) throw std::runtime_error("truncated DEFLATE stream"); uint32_t v=0; for(unsigned i=0;i<n;++i) v|=uint32_t((s[(p+i)>>3]>>((p+i)&7))&1)<<i; p+=n; return v; }
        void align() { p=(p+7)&~size_t(7); }
    } bits{src};
    struct Huff {
        unsigned maxlen=0; std::vector<std::vector<int>> tab;
        explicit Huff(const std::vector<uint8_t>& lens) : tab(16) {
            std::array<unsigned,16> count{},next{};
            for(uint8_t n:lens) { if(n>15) throw std::runtime_error("invalid DEFLATE Huffman length"); if(n){++count[n]; maxlen=std::max(maxlen,unsigned(n));} }
            unsigned code=0; for(unsigned n=1;n<=15;++n){code=(code+count[n-1])<<1; next[n]=code; if(code+count[n]>(1U<<n)) throw std::runtime_error("oversubscribed DEFLATE tree");}
            for(unsigned n=1;n<=maxlen;++n) tab[n].assign(size_t(1)<<n,-1);
            for(size_t sym=0;sym<lens.size();++sym) if(unsigned n=lens[sym]) { unsigned c=next[n]++,r=0; for(unsigned i=0;i<n;++i) r=(r<<1)|((c>>i)&1); tab[n][r]=int(sym); }
        }
        int read(Bits& b) const { unsigned c=0; for(unsigned n=1;n<=maxlen;++n){c|=b.get(1)<<(n-1); if(tab[n][c]>=0)return tab[n][c];} throw std::runtime_error("invalid DEFLATE Huffman code"); }
    };
    auto fixed=[](){ std::vector<uint8_t> ll(288),dd(32,5); for(unsigned i=0;i<=143;++i)ll[i]=8; for(unsigned i=144;i<=255;++i)ll[i]=9; for(unsigned i=256;i<=279;++i)ll[i]=7; for(unsigned i=280;i<=287;++i)ll[i]=8; return std::pair<Huff,Huff>{Huff(ll),Huff(dd)}; };
    std::vector<uint8_t> out; out.reserve(out_size); bool final=false;
    static const unsigned lbase[29]={3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const uint8_t lextra[29]={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const unsigned dbase[30]={1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const uint8_t dextra[30]={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    while(!final) {
        final=bits.get(1)!=0; unsigned kind=bits.get(2);
        if(kind==0) { bits.align(); unsigned len=bits.get(16),inv=bits.get(16); if((len^0xffffU)!=inv)throw std::runtime_error("invalid DEFLATE stored block"); if(len>out_size-out.size())throw std::runtime_error("DEFLATE output overflow"); while(len--)out.push_back(uint8_t(bits.get(8))); continue; }
        if(kind==3) throw std::runtime_error("reserved DEFLATE block type");
        Huff lit(std::vector<uint8_t>{}),dist(std::vector<uint8_t>{});
        if(kind==1) { auto h=fixed(); lit=std::move(h.first); dist=std::move(h.second); }
        else {
            unsigned nl=bits.get(5)+257,nd=bits.get(5)+1,nc=bits.get(4)+4; static const uint8_t order[19]={16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            std::vector<uint8_t> cl(19); for(unsigned i=0;i<nc;++i)cl[order[i]]=uint8_t(bits.get(3)); Huff ch(cl); std::vector<uint8_t> lens; lens.reserve(nl+nd);
            while(lens.size()<nl+nd) { int s=ch.read(bits); if(s<=15)lens.push_back(uint8_t(s)); else { unsigned rep; uint8_t value=0; if(s==16){if(lens.empty())throw std::runtime_error("invalid DEFLATE repeat"); value=lens.back(); rep=bits.get(2)+3;} else if(s==17)rep=bits.get(3)+3; else if(s==18)rep=bits.get(7)+11; else throw std::runtime_error("invalid DEFLATE code-length symbol"); if(rep>nl+nd-lens.size())throw std::runtime_error("DEFLATE repeat overflow"); lens.insert(lens.end(),rep,value); } }
            lit=Huff(std::vector<uint8_t>(lens.begin(),lens.begin()+nl)); dist=Huff(std::vector<uint8_t>(lens.begin()+nl,lens.end()));
        }
        for(;;) { int s=lit.read(bits); if(s<256){if(out.size()==out_size)throw std::runtime_error("DEFLATE output overflow");out.push_back(uint8_t(s));continue;} if(s==256)break; if(s<257||s>285)throw std::runtime_error("invalid DEFLATE length"); unsigned li=unsigned(s-257),len=lbase[li]+bits.get(lextra[li]); int ds=dist.read(bits); if(ds<0||ds>=30)throw std::runtime_error("invalid DEFLATE distance"); size_t d=dbase[ds]+bits.get(dextra[ds]); if(!d||d>out.size()||len>out_size-out.size())throw std::runtime_error("invalid DEFLATE back-reference"); while(len--)out.push_back(out[out.size()-d]); }
    }
    if(out.size()!=out_size) throw std::runtime_error("DEFLATE size mismatch");
    return out;
}

struct Volume { uint32_t sector_size{}; uint64_t start_lba{}, data_offset{}; };
struct Metadata { uint32_t flags{},compression{},format_version{}; bool encrypted{}; uint64_t disk_size{}; std::vector<uint8_t> boot_data; std::vector<Volume> volumes; };
static Metadata metadata(std::ifstream& in,bool verbose) {
    Metadata m; bool first=true;
    for(;;) {
        uint64_t off=uint64_t(in.tellg()); Record r=read_record(in); if(r.type==0xffffffffU) break;
        if(verbose) std::cerr<<"metadata @"<<off<<" type="<<r.type<<" size="<<r.size<<"\n";
        if(first) {
            if(r.type||r.size!=28||std::memcmp(r.data.data(),"IMG2\0",5)) throw std::runtime_error("not an IMG2 TBI image");
            m.flags=le32(r.data.data()+16); m.format_version=le32(r.data.data()+24);
            m.compression=(m.flags&1)?1:(m.flags&0x40)?11:(m.flags&0x20)?14:0; first=false;
            if(verbose) std::cerr<<"IMG2 format=0x"<<std::hex<<m.format_version<<" flags=0x"<<m.flags<<std::dec<<" compression="<<m.compression<<"\n";
        } else if(r.type==6&&!r.data.empty()) m.encrypted=r.data[0]!=0;
        else if(r.type==4&&r.data.size()>=28) {
            uint32_t header_size=le32(r.data.data());
            size_t expanded=le16(r.data.data()+24); if(!expanded) expanded=65536;
            size_t stored=le16(r.data.data()+26); if(!stored) stored=65536;
            if(header_size>r.data.size()||stored>r.data.size()-header_size) throw std::runtime_error("invalid type-4 disk metadata");
            std::vector<uint8_t> packed(r.data.begin()+header_size,r.data.begin()+header_size+stored);
            if(stored==expanded) m.boot_data=std::move(packed);
            else if(m.compression==1) m.boot_data=decode_deflate(packed,expanded);
            else if(m.compression==14||m.compression==15) m.boot_data=decode_lz(packed,expanded);
            else if(m.compression==0) m.boot_data=decode_legacy(packed,expanded);
            else throw std::runtime_error("unsupported type-4 metadata compression");
            uint32_t disk_sector=le32(r.data.data()+8);
            if(disk_sector&&m.boot_data.size()>=disk_sector+40&&std::memcmp(m.boot_data.data()+disk_sector,"EFI PART",8)==0)
                m.disk_size=(le64(m.boot_data.data()+disk_sector+32)+1)*uint64_t(disk_sector);
        }
        else if(r.type==1&&r.data.size()>=180) {
            // Legacy 276-byte descriptors are converted internally by moving
            // bytes 44..275 to offset 108 in the modern 408-byte layout.
            const bool legacy=r.data.size()<408;
            const size_t start_off=legacy?44:108;
            const size_t data_off=legacy?172:236;
            Volume v{le32(r.data.data()+4),le64(r.data.data()+start_off),le64(r.data.data()+data_off)};
            if(!v.sector_size||(v.sector_size&(v.sector_size-1))||v.sector_size>65536) throw std::runtime_error("invalid sector size");
            m.volumes.push_back(v);
        }
    }
    if(first||m.volumes.empty()) throw std::runtime_error("missing TBI header or volume descriptors");
    return m;
}
static bool control_record(const std::vector<uint8_t>& d,Record& r) {
    if(d.size()<12) return false;
    r={le32(d.data()),le32(d.data()+4),le32(d.data()+8),{}};
    if(r.type>3||r.size!=d.size()-12) return false;
    r.data.assign(d.begin()+12,d.end());
    return r.check==((r.type+r.size)^tbi_hash(r.data.data(),r.data.size()));
}
static void seek_output(std::fstream& out,uint64_t pos) {
    if(pos>uint64_t(std::numeric_limits<std::streamoff>::max())) throw std::runtime_error("output offset too large");
    out.seekp(static_cast<std::streamoff>(pos)); if(!out) throw std::runtime_error("output seek failed");
}
static void ensure_output_size(std::fstream& out,uint64_t size) {
    if(!size) return;
    out.clear(); out.seekp(0,std::ios::end);
    const auto current=out.tellp();
    if(current<0) throw std::runtime_error("cannot determine output size");
    if(static_cast<uint64_t>(current)<size) {
        seek_output(out,size-1); const char zero=0; out.write(&zero,1);
    }
}

// Original Image for DOS/Linux ("IMG\0") format, as used by IMAGEL 1.99.
// Its 68-byte header is padded to one sector.  The remainder consists of
// uint16_t expanded/stored sizes followed by a legacy-compressed chunk.  The
// expanded byte stream contains five-byte sparse-run commands:
//   0, sector_count     skip sectors
//   1, sector_count     the following bytes are allocated sector data
//   *, 0xffffffff       end of commands in this expanded chunk
static uint16_t legacy_chunk_hash(const std::vector<uint8_t>& data) {
    uint16_t h=0;
    for(size_t off=0;off+1<data.size();off+=2) {
        const uint16_t word=le16(data.data()+off);
        h=uint16_t(word+uint16_t((uint16_t(h<<8))^h));
    }
    return h;
}

static std::string ascii_lower(std::string value) {
    for(char& c:value) c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static fs::path find_legacy_segment(const fs::path& first,unsigned number) {
    char extension[5]{};
    std::snprintf(extension,sizeof(extension),".%03u",number);
    const fs::path wanted=first.parent_path()/(first.stem().string()+extension);
    if(fs::exists(wanted)) return wanted;

    // ISO contents are often copied between case-sensitive and
    // case-insensitive file systems (part0.img plus PART0.001).
    const std::string wanted_name=ascii_lower(wanted.filename().string());
    const fs::path directory=first.parent_path().empty()?fs::path("."):first.parent_path();
    for(const auto& entry:fs::directory_iterator(directory))
        if(entry.is_regular_file()&&ascii_lower(entry.path().filename().string())==wanted_name)
            return entry.path();
    return {};
}

static fs::path find_tbi_segment(const fs::path& first,unsigned number) {
    const fs::path wanted=first.parent_path()/(first.stem().string()+"."+std::to_string(number));
    if(fs::exists(wanted)) return wanted;
    const std::string wanted_name=ascii_lower(wanted.filename().string());
    const fs::path directory=first.parent_path().empty()?fs::path("."):first.parent_path();
    for(const auto& entry:fs::directory_iterator(directory))
        if(entry.is_regular_file()&&ascii_lower(entry.path().filename().string())==wanted_name)
            return entry.path();
    return {};
}

class TbiSegmentedInput {
public:
    TbiSegmentedInput(const fs::path& first,bool verbose):verbose_(verbose) {
        paths_.push_back(first); sizes_.push_back(fs::file_size(first));
        for(unsigned number=1;;++number) {
            fs::path next=find_tbi_segment(first,number);
            if(next.empty()) break;
            paths_.push_back(next); sizes_.push_back(fs::file_size(next));
        }
        open_segment(0,0);
    }

    uint64_t tell() const { return position_; }
    bool eof() const { return position_==total_size(); }

    void seek(uint64_t position) {
        uint64_t base=0;
        for(size_t index=0;index<paths_.size();++index) {
            if(position<base+sizes_[index]||(position==base+sizes_[index]&&index+1==paths_.size())) {
                open_segment(index,position-base); position_=position; return;
            }
            base+=sizes_[index];
        }
        throw std::runtime_error("TBI data offset exceeds the available split image files");
    }

    void read_exact(void* destination,size_t size,const char* what) {
        auto* bytes=static_cast<char*>(destination);
        size_t done=0;
        while(done<size) {
            const uint64_t local=local_position();
            if(local==sizes_[index_]) {
                if(index_+1>=paths_.size()) throw std::runtime_error(std::string("truncated ")+what);
                open_segment(index_+1,0);
                if(verbose_) std::cerr<<"continuing with "<<paths_[index_].filename().string()<<"\n";
                continue;
            }
            const size_t take=static_cast<size_t>(std::min<uint64_t>(size-done,sizes_[index_]-local));
            file_.read(bytes+done,static_cast<std::streamsize>(take));
            if(static_cast<size_t>(file_.gcount())!=take) throw std::runtime_error(std::string("truncated ")+what);
            done+=take; position_+=take;
        }
    }

private:
    uint64_t total_size() const {
        uint64_t total=0; for(uint64_t size:sizes_) total+=size; return total;
    }
    uint64_t segment_base(size_t index) const {
        uint64_t base=0; for(size_t i=0;i<index;++i) base+=sizes_[i]; return base;
    }
    uint64_t local_position() const { return position_-segment_base(index_); }
    void open_segment(size_t index,uint64_t local) {
        file_.close(); file_.clear(); file_.open(paths_[index],std::ios::binary);
        if(!file_) throw std::runtime_error("cannot open split image segment "+paths_[index].string());
        file_.seekg(static_cast<std::streamoff>(local));
        if(!file_) throw std::runtime_error("cannot seek split image segment "+paths_[index].string());
        index_=index;
    }

    std::vector<fs::path> paths_;
    std::vector<uint64_t> sizes_;
    std::ifstream file_;
    size_t index_=0;
    uint64_t position_=0;
    bool verbose_=false;
};

static void convert_img1(std::ifstream& in,const fs::path& src,const fs::path& dst,bool verbose) {
    std::array<uint8_t,512> header{};
    in.clear(); in.seekg(0); read_exact(in,header.data(),header.size(),"legacy IMG header");
    if(std::memcmp(header.data(),"IMG\0",4)) throw std::runtime_error("not a legacy IMG image");

    const uint64_t total_sectors=le32(header.data()+4);
    if(!total_sectors) throw std::runtime_error("legacy IMG has an invalid sector count");
    const uint64_t logical_size=total_sectors*512U;
    const uint32_t expected_hash=le32(header.data()+52);
    const uint16_t tail_padding=le16(header.data()+10);
    const uint64_t physical_sectors=le32(header.data()+14);
    if(!physical_sectors||physical_sectors>(std::numeric_limits<uint64_t>::max()-512U)/512U)
        throw std::runtime_error("legacy IMG has an invalid physical size");
    const uint64_t input_size=512U+physical_sectors*512U;
    if(input_size<512U+tail_padding) throw std::runtime_error("invalid legacy IMG padding");
    const uint64_t stream_size=input_size-512U-tail_padding;

    std::vector<fs::path> segments{src};
    uint64_t available=fs::file_size(src);
    for(unsigned number=1;available<input_size;++number) {
        if(number>999) throw std::runtime_error("legacy IMG has too many split segments");
        fs::path next=find_legacy_segment(src,number);
        if(next.empty()) {
            char extension[5]{}; std::snprintf(extension,sizeof(extension),".%03u",number);
            throw std::runtime_error("missing split image segment "+(src.stem().string()+extension));
        }
        const uint64_t segment_size=fs::file_size(next);
        if(segment_size>input_size-available)
            throw std::runtime_error("split image segments exceed the size declared by the IMG header");
        segments.push_back(std::move(next)); available+=segment_size;
    }
    if(available!=input_size) throw std::runtime_error("legacy IMG physical size mismatch");

    in.close();
    size_t segment_index=0;
    std::ifstream segment_in(segments.front(),std::ios::binary);
    segment_in.seekg(512);
    uint64_t consumed=0;
    auto read_segmented=[&](void* destination,size_t size,const char* what) {
        auto* out_bytes=static_cast<char*>(destination);
        size_t done=0;
        while(done<size) {
            segment_in.read(out_bytes+done,static_cast<std::streamsize>(size-done));
            const size_t got=static_cast<size_t>(segment_in.gcount());
            done+=got; consumed+=got;
            if(done==size) break;
            if(!segment_in.eof()||++segment_index>=segments.size())
                throw std::runtime_error(std::string("truncated ")+what);
            segment_in.close(); segment_in.clear();
            segment_in.open(segments[segment_index],std::ios::binary);
            if(!segment_in) throw std::runtime_error("cannot open split image segment "+segments[segment_index].string());
            if(verbose) std::cerr<<"continuing with "<<segments[segment_index].filename().string()<<"\n";
        }
    };

    std::fstream out(dst,std::ios::binary|std::ios::in|std::ios::out|std::ios::trunc);
    if(!out) throw std::runtime_error("cannot create output");

    uint64_t sector=0,pending_bytes=0,written=0,blocks=0;
    uint32_t stream_hash=0;
    bool terminated=false;
    while(!terminated) {
        if(consumed==stream_size) { terminated=true; break; }
        if(consumed>stream_size||stream_size-consumed<4) throw std::runtime_error("truncated legacy block header");
        std::array<uint8_t,4> bh{};
        read_segmented(bh.data(),bh.size(),"legacy block header");
        const size_t expanded_size=le16(bh.data());
        const size_t stored_size=le16(bh.data()+2);
        if(!expanded_size||!stored_size) throw std::runtime_error("invalid legacy block size");
        if(stored_size>stream_size-consumed) throw std::runtime_error("truncated legacy block payload");
        std::vector<uint8_t> packed(stored_size);
        read_segmented(packed.data(),packed.size(),"legacy block payload");
        std::vector<uint8_t> expanded=stored_size==expanded_size
            ? std::move(packed) : decode_legacy(packed,expanded_size);
        stream_hash+=legacy_chunk_hash(expanded);
        ++blocks;

        size_t pos=0;
        while(pos<expanded.size()) {
            if(pending_bytes) {
                const size_t take=static_cast<size_t>(std::min<uint64_t>(pending_bytes,expanded.size()-pos));
                if(take%512) throw std::runtime_error("legacy data run is not sector aligned");
                if(sector>total_sectors||take/512>total_sectors-sector)
                    throw std::runtime_error("legacy data run exceeds partition size");
                seek_output(out,sector*512U);
                out.write(reinterpret_cast<const char*>(expanded.data()+pos),static_cast<std::streamsize>(take));
                if(!out) throw std::runtime_error("output write failed");
                pos+=take; pending_bytes-=take; sector+=take/512; written+=take;
                continue;
            }
            if(expanded.size()-pos<5) throw std::runtime_error("truncated legacy run command");
            const uint8_t kind=expanded[pos];
            const uint32_t count=le32(expanded.data()+pos+1);
            pos+=5;
            if(count==0xffffffffU) break;
            if(!kind) {
                if(count>total_sectors-sector) throw std::runtime_error("legacy sparse run exceeds partition size");
                sector+=count;
                if(sector==total_sectors) { terminated=true; break; }
            } else {
                if(count>total_sectors-sector) throw std::runtime_error("legacy allocated run exceeds partition size");
                pending_bytes=uint64_t(count)*512U;
            }
        }
        if(verbose&&!(blocks%1024)) std::cerr<<"legacy blocks="<<blocks<<" wrote="<<(written>>20)<<" MiB\r";
    }
    if(pending_bytes) throw std::runtime_error("legacy image ended with an incomplete data run");
    if(expected_hash&&stream_hash!=expected_hash) throw std::runtime_error("legacy stream checksum mismatch");
    if(sector>total_sectors) throw std::runtime_error("legacy image exceeds declared partition size");
    ensure_output_size(out,logical_size); out.flush();
    if(!out) throw std::runtime_error("cannot finalize output");
    std::cerr<<"Converted legacy IMG: "<<blocks<<" blocks; wrote "<<(written>>20)
             <<" MiB; logical size "<<(logical_size>>20)<<" MiB\n";
}

static void convert(const fs::path& src,const fs::path& dst,bool verbose) {
    std::ifstream in(src,std::ios::binary); if(!in) throw std::runtime_error("cannot open input");
    std::array<uint8_t,4> magic{}; read_exact(in,magic.data(),magic.size(),"image signature");
    in.clear(); in.seekg(0);
    if(!std::memcmp(magic.data(),"IMG\0",4)) { convert_img1(in,src,dst,verbose); return; }
    Metadata m=metadata(in,verbose);
    TbiSegmentedInput image_files(src,verbose);
    if(m.encrypted) throw std::runtime_error("encrypted images are not supported");
    if(m.compression!=0&&m.compression!=1&&m.compression!=14&&m.compression!=15) throw std::runtime_error("unsupported compression option "+std::to_string(m.compression));
    std::fstream out(dst,std::ios::binary|std::ios::in|std::ios::out|std::ios::trunc); if(!out) throw std::runtime_error("cannot create output");
    uint64_t blocks=0,written=0,max_end=0;
    if(!m.boot_data.empty()) {
      out.write(reinterpret_cast<const char*>(m.boot_data.data()),static_cast<std::streamsize>(m.boot_data.size()));
      if(!out) throw std::runtime_error("cannot write disk boot metadata");
      max_end=m.boot_data.size(); written+=m.boot_data.size();
      if(verbose) std::cerr<<"restored "<<m.boot_data.size()<<" bytes of MBR/GPT metadata\n";
    }
    for(size_t vi=0;vi<m.volumes.size();++vi) {
      const Volume& volume=m.volumes[vi];
      uint32_t sector=volume.sector_size; uint64_t lba=volume.start_lba,pending=0;
      uint64_t data_off=volume.data_offset;
      try { image_files.seek(data_off); }
      catch(const std::exception&) { throw std::runtime_error("invalid data offset for volume "+std::to_string(vi)); }
      if(verbose) std::cerr<<"volume "<<vi<<" data_offset="<<data_off<<" start_lba="<<lba<<" sector_size="<<sector<<"\n";
      bool volume_done=false;
      while(!volume_done&&!image_files.eof()) {
        std::array<uint8_t,8> h{}; size_t header_size=(m.flags&0x80)?8:4; image_files.read_exact(h.data(),header_size,"block header");
        uint16_t ef=le16(h.data()),sf=le16(h.data()+2); uint32_t expected=le32(h.data()+4);
        size_t flagged=ef?ef:65536U,expanded_size=flagged&~size_t(1),stored_size=sf?sf:65536U; std::vector<uint8_t> packed(stored_size);
        image_files.read_exact(packed.data(),packed.size(),"block payload"); ++blocks;
        Record ctl; if(expanded_size==stored_size&&control_record(packed,ctl)) {
            if(ctl.type==2) { volume_done=true; continue; }
            if(ctl.type==3&&ctl.data.size()>=4) lba+=le32(ctl.data.data());
            // Type 0/1 controls carry stream bookkeeping. Physical file
            // transitions are handled transparently by TbiSegmentedInput.
            continue;
        }
        std::vector<uint8_t> expanded;
        if(stored_size==expanded_size) expanded=packed;
        else if(m.compression==1) expanded=decode_deflate(packed,expanded_size);
        else if(m.compression==14||m.compression==15) expanded=decode_lz(packed,expanded_size);
        else if(m.compression==0) expanded=decode_legacy(packed,expanded_size);
        else throw std::runtime_error("compressed block in uncompressed image");
        uint32_t mix=(uint32_t(sf)<<16)|ef;
        if(header_size==8&&expected!=(tbi_hash(packed.data(),packed.size())^mix)&&expected!=(tbi_hash(expanded.data(),expanded.size())^mix))
            throw std::runtime_error("block checksum mismatch at block "+std::to_string(blocks));
        // The original restore loop distinguishes a map from sector data by
        // whether an allocated run is outstanding.  Bit 0 of the expanded
        // size is normally set on maps, but it is not the state machine.
        if(pending) {
            if(expanded.size()%sector) throw std::runtime_error("data block is not sector aligned");
            uint64_t count=expanded.size()/sector;
            if(pending&&count>pending) throw std::runtime_error("data block exceeds allocated run");
            seek_output(out,lba*uint64_t(sector));
            out.write(reinterpret_cast<const char*>(expanded.data()),static_cast<std::streamsize>(expanded.size())); if(!out) throw std::runtime_error("output write failed");
            lba+=count; if(pending) pending-=count; written+=expanded.size(); max_end=std::max(max_end,lba*uint64_t(sector));
        } else {
            if(expanded.size()<4) throw std::runtime_error("short run map");
            size_t n=expanded.size()-4;
            const uint32_t wanted=le32(expanded.data()+n),got=tbi_hash(expanded.data(),n);
            if(n%4||wanted!=got) throw std::runtime_error("run-map checksum mismatch at block "+std::to_string(blocks)+
                " (stored="+std::to_string(stored_size)+", expanded="+std::to_string(expanded_size)+
                ", expected="+std::to_string(wanted)+", calculated="+std::to_string(got)+")");
            bool terminated=false;
            for(size_t off=0;off<n;off+=4) {
                uint32_t w=le32(expanded.data()+off),kind=w&0xf0000000U,count=w&0x0fffffffU;
                // Image for Linux 2.x DecompressLoop: nonzero kinds advance
                // across holes.  The terminal zero-kind entry supplies the
                // allocated-sector count consumed by the following blocks.
                if(!kind) { pending=count; terminated=true; break; }
                lba+=count; max_end=std::max(max_end,lba*uint64_t(sector));
            }
            if(!terminated) throw std::runtime_error("run map has no terminal allocated run");
        }
        if(verbose&&!(blocks%4096)) std::cerr<<"blocks="<<blocks<<" written="<<(written>>20)<<" MiB\r";
      }
      if(!volume_done) throw std::runtime_error("volume stream ended without a type-2 terminator");
      if(pending) throw std::runtime_error("volume ended with an incomplete allocated run");
    }
    max_end=std::max(max_end,m.disk_size);
    // Type 4 stores the primary GPT area. Recreate the conventional backup
    // entry array and header at the end of the original disk.
    if(m.disk_size&&m.boot_data.size()>=1024&&std::memcmp(m.boot_data.data()+512,"EFI PART",8)==0) {
      const uint8_t* primary=m.boot_data.data()+512; uint32_t hs=le32(primary+12),count=le32(primary+80),esz=le32(primary+84);
      uint64_t entries_lba=le64(primary+72),backup_lba=le64(primary+32),array_bytes=uint64_t(count)*esz;
      if(hs>=92&&hs<=512&&array_bytes<=64U*1024U*1024U&&entries_lba*512+array_bytes<=m.boot_data.size()) {
        uint64_t backup_entries=backup_lba-(array_bytes+511)/512;
        seek_output(out,backup_entries*512); out.write(reinterpret_cast<const char*>(m.boot_data.data()+entries_lba*512),static_cast<std::streamsize>(array_bytes));
        std::array<uint8_t,512> bh{}; std::memcpy(bh.data(),primary,hs); put64(bh.data()+24,backup_lba); put64(bh.data()+32,1); put64(bh.data()+72,backup_entries); put32(bh.data()+16,0); put32(bh.data()+16,crc32(bh.data(),hs));
        seek_output(out,backup_lba*512); out.write(reinterpret_cast<const char*>(bh.data()),bh.size());
      }
    }
    ensure_output_size(out,max_end); out.flush();
    std::cerr<<"Converted "<<blocks<<" blocks; wrote "<<(written>>20)<<" MiB; logical size "<<(max_end>>20)<<" MiB\n";
}
int main(int argc,char** argv) {
    try {
        bool verbose=false;
        std::vector<std::string> positional;
        for(int i=1;i<argc;++i) {
            const std::string arg=argv[i];
            if(arg=="--verbose") verbose=true;
            else if(!arg.empty()&&arg[0]=='-') {
                std::cerr<<"tbi2img: unknown option "<<arg<<"\n";
                return 2;
            } else positional.push_back(arg);
        }
        if(positional.size()!=2) {
            std::cerr<<"Usage: tbi2img [--verbose] <input.tbi> <output.img>\n";
            return 2;
        }
        convert(positional[0],positional[1],verbose);
        return 0;
    }
    catch(const std::exception& e){std::cerr<<"tbi2img: "<<e.what()<<"\n";return 1;}
}
