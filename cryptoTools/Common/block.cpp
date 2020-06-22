#include "block.h"

#include "Defines.h"
#include <iomanip>

namespace osuCrypto
{

	const block ZeroBlock = toBlock(0, 0);
	const block OneBlock = toBlock(0, 1);
	const block AllOneBlock = toBlock(u64(-1), u64(-1));
	const std::array<block, 2> zeroAndAllOne = { { ZeroBlock, AllOneBlock } };
	const block CCBlock = toBlock(0xcccccccccccccccc, 0xcccccccccccccccc);
	// ([]() {block cc; memset(&cc, 0xcc, sizeof(block)); return cc; })();

}


std::ostream& operator<<(std::ostream& out, const oc::block& blk)
{
	using namespace oc;
	out << std::hex;
	u64* data = (u64*)&blk;

	out << std::setw(16) << std::setfill('0') << data[1]
		<< std::setw(16) << std::setfill('0') << data[0];

	out << std::dec << std::setw(0);
	return out;
}