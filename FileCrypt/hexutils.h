#include <xstring>

using namespace std;

namespace filecrypt
{
	namespace utils
	{
		class HexUtils
		{
		public:
			template <typename T> static string hexify(T const & x){
				return hexify(x, sizeof x);
			};

			template <typename T> static string hexify(T const & x, size_t size_of_x){
				char const alphabet[] = "0123456789ABCDEF";

				std::string result(2 * size_of_x, 0);
				unsigned char const * const p = reinterpret_cast<unsigned char const *>(&x);

				for (std::size_t i = 0; i != size_of_x; i ++)
				{
					result[2 * i    ] = alphabet[p[i] / 16];
					result[2 * i + 1] = alphabet[p[i] % 16];
				}

				return result;
			};
		};
	}
}