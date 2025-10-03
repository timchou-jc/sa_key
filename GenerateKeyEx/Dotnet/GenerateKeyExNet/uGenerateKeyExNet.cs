using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GenerateKeyExNet
{
	public class uGenerateKeyExNet
	{
		/// <summary>
		/// GenerateKeyEx
		/// </summary>
		/// <param name="ipSeedArray"></param>
		/// <param name="iSeedArraySize"></param>
		/// <param name="iSecurityLevel"></param>
		/// <param name="ipVariant"></param>
		/// <param name="iopKeyArray"></param>
		/// <param name="iMaxKeyArraySize"></param>
		/// <param name="oActualKeyArraySize"></param>
		/// <returns></returns>
		public static int GenerateKeyEx(
				byte[] ipSeedArray,            /* Array for the seed [in] */
				uint iSeedArraySize,           /* Length of the array for the seed [in] */
				uint iSecurityLevel,           /* Security level [in] */
				char[] ipVariant,              /* Name of the active variant [in] */
				byte[] iopKeyArray,            /* Array for the key [in, out] */
				uint iMaxKeyArraySize,         /* Maximum length of the array for the key [in] */
				uint[] oActualKeyArraySize)    /* Length of the key [out] */
		{
			iopKeyArray[0] = 0x03;
			iopKeyArray[1] = 0x33;
			iopKeyArray[2] = 0x56;
			iopKeyArray[3] = 0x68;
			if (oActualKeyArraySize.Count() > 0)
			{
				oActualKeyArraySize[0] = 4;
			}
			return 0;
		}

		/// <summary>
		/// ASAP1A_CCP_ComputeKeyFromSeed
		/// </summary>
		/// <param name="ipSeedArray"></param>
		/// <param name="iSeedArraySize"></param>
		/// <param name="opKey"></param>
		/// <param name="maxSizeKey"></param>
		/// <param name="opSizeKey"></param>
		/// <returns></returns>
		public static int ASAP1A_CCP_ComputeKeyFromSeed(
			                             byte[] ipSeedArray,          /* Array for the seed [in] */
										 uint iSeedArraySize,               /* Length of the array for the seed [in] */
										 byte[] opKey,                /* Array for the key [in, out] */
										 uint maxSizeKey,                   /* Maximum length of the array for the key [in] */
										 uint[] opSizeKey)                    /* Length of the key [out] */
		{
			if (opSizeKey.Count() > 0)
			{
				opSizeKey[0] = 4;
			}
			return 0;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ASeed"></param>
		/// <param name="AKey"></param>
		/// <returns></returns>
		public static int SeedAndKey_Type2(UInt32 ASeed, ref UInt32 AKey)
		{
			return 0;
		}

	}
}
