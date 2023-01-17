/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef HELPER_H
#define HELPER_H

#include <string>

namespace ns3 {

char *IntToStr(int num);

// can handle positive 0x 0b or normal digit,eg 0x12a, 0b001, 123
unsigned int StrToInt(const std::string& str);

// can handle positive digit,eg 12.34
double StrToDouble(const std::string& str);

/**
 * @brief transfer "a" hex char to int
 * 
 * @param c 
 * @return int 
 */
int HexcharToInt(char c);

/**
 * @brief transfer hexadecimal to decimal. For example: if the 
 * input is "0x0a010001" and first step remove the prefix "0x",
 * then init the result string with length 8/2=4 (8 is length 
 * of str "0a010001"), save "10","1","0","1" in to result string.
 * and the result will be a string "'10','1','0','1'" with 4 length.
 * 
 * @param str string hexadecimal number
 * @return std::string
 */
std::string HexstrToBytes(const std::string& str);

/**
 * @brief transfer hexadecimal to Bytes flow. For example: if the 
 * input is "0x0a010001" and 24.
 * The first step is remove the prefix "0x", then init the result 
 * string with length 24/8=3, Check 0a010001 by loop, which can 
 * only check to "0a0100", and save "10","1","0" in to result string.
 * and the result will be a string "'10','1','0'" with 3 length.
 * 
 * @param str 
 * @param bitWidth with 32(full ip), 24(The first three segments of ip), 16, 8
 * @return std::string
 */
std::string HexstrToBytes(const std::string& str, unsigned int bitWidth);

/**
 * @brief transfer ip address to Bytes flow
 * for example: "10.1.0.1"  ---> "'10','1','0','1'" with length 4.
 * @param str 
 * @return std::string 
 */
std::string IpStrToBytes(const std::string& str);

/**
 * @brief transfer ip address to Bytes flow
 * for example: "10.1.0.1" and 3 ---> "'10','1','0'" with length 3.
 * @param str 
 * @param bitWidth with 32(full ip), 24(The first three segments of ip), 16, 8
 * @return std::string 
 */
std::string IpStrToBytes(const std::string& str, unsigned int bitWidth);

std::string UintToString(unsigned int num);

std::string Uint32ipToHex(unsigned int ip);

}//namespace ns3
#endif /* HELPER_H */
