/**********************************************************************************
    First Growtopia Private Server made with ENet.
    Copyright (C) 2018  Growtopia Noobs
    Made by Jordan#0495

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/


#include "stdafx.h"
#include <iostream>
#include "enet/enet.h"
#include <string>
#include <windows.h>
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.c"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.c"
#include "crypt_blowfish/wrapper.c"
#include "bcrypt.c"
#include <conio.h>
#include <thread> // TODO
#include <mutex> // TODO

using namespace std;
using json = nlohmann::json;

//#define TOTAL_LOG
#define REGISTRATION

ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;

/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret;
	
	 ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);
	
	return !ret;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;
	
	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data+4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i<strleng)
	{
		int j = 0;
		while (i + j<strleng && j<delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};


GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n+p.len+2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data+p.len, &zero, 1);
	p.len += 1;
	//*(int*)(p.data + 52) = p.len;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}

struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 1000;
};

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace

struct PlayerInfo {
	bool isIn = false;
	int netID;
	bool haveGrowId = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	int adminLevel = 0;
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	bool isRotatedLeft = false;

	bool isUpdating = false;
	bool joinClothesUpdated = false;

	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	//bool 
	int skinColor = 0x8295C3FF;

	PlayerInventory inventory;

	long long int lastSB = 0;
	long long int lastBC = 0;
	long long int lastVSB = 0;
};


int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
	return val;
}


struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;

};

struct WorldInfo {
	int width = 100;
	int height = 60;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	bool isPublic=false;
	int weather = 0;
};

WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i<5400 && !(rand() % 50))
			world.items[i].foreground = 10;
		else if (i >= 3700 && i<5400)
		{
			world.items[i].foreground = 2;
		}
		else if (i >= 5400) {
			world.items[i].foreground = 8;
		}
		if (i >= 3700)
			world.items[i].background = 0;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i<3700)
			world.items[i].foreground = 16;
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}


class PlayerDB {
public:
	static string getProperName(string name);
	static string PlayerDB::fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(string username, string password);
};

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS+=(c >= 'A' && c <= 'Z') ? c-('A'-'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;
	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];
			
			
			if (i+1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		} else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}

int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		string geyban = j["isBanned"];

		if (geyban == "true") {
			return -3;
		}
		if (verifyPassword(password, pss)) {
			ENetPeer * currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(username))
				{
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else logged to this account!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
					}
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else was logged to this account! He was kicked out now."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					//enet_host_flush(server);
					enet_peer_disconnect_later(currentPeer, 0);
				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}

int PlayerDB::playerRegister(string username, string password) {
	username = PlayerDB::getProperName(username);
	if (username.length() < 3) return -2;
	std::ifstream ifs("players/" + username + ".json");
	if (ifs.is_open()) {
		return -1;
	}

	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	PlayerInfo pinfo;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["isBanned"] = "false";
	j["adminLevel"] = 0;
	j["ClothBack"] = 0;
	j["ClothHand"] = 0;
	j["ClothFace"] = 0;
	j["ClothShirt"] = 0;
	j["ClothPants"] = 0;
	j["ClothNeck"] = 0;
	j["ClothHair"] = 0;
	j["ClothFeet"] = 0;
	j["ClothMask"] = 0;
	o << j << std::endl;
	return 1;
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	AWorld get2(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
#ifdef TOTAL_LOG
		cout << "Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "Redundant worlds are saved!" << endl;
#endif
	}
	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c<'A' || c>'Z') && (c<'0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"];
		info.width = j["width"];
		info.height = j["height"];
		info.owner = j["owner"];
		info.isPublic = j["isPublic"];
		json tiles = j["tiles"];
		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["owner"] = info.owner;
	j["isPublic"] = info.isPublic;
	j["weather"] = info.weather;
	json tiles = json::array();
	int square = info.width*info.height;
	
	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));
		delete worlds.at(i).items;
	}
	worlds.clear();
}
void setBanned(string boolean, string username, string password, string passwordverify, string email, string discord, string ClothBack, string ClothHand, string ClothFace, string ClothShirt, string ClothPant, string ClothNeck, string ClothHair, string ClothFeet, string ClothMask, string Level, string block, string isBanned) {
	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	PlayerInfo pinfo;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["discord"] = discord;
	j["adminLevel"] = 0;
	j["ClothBack"] = 0;
	j["ClothHand"] = 0;
	j["ClothFace"] = 0;
	j["ClothShirt"] = 0;
	j["ClothPants"] = 0;
	j["ClothNeck"] = 0;
	j["ClothHair"] = 0;
	j["ClothFeet"] = 0;
	j["ClothMask"] = 0;
	j["Level"] = 0;
	j["block"] = 0;
	j["isBanned"] = boolean;
	o << j << std::endl;
}

void unbangay(string boolean, string username) {
	string pss = "";
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
	}

	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json js;
	PlayerInfo pinfo;
	js["username"] = username;
	js["password"] = pss;
	js["adminLevel"] = 0;
	js["ClothBack"] = 0;
	js["ClothHand"] = 0;
	js["ClothFace"] = 0;
	js["ClothShirt"] = 0;
	js["ClothPants"] = 0;
	js["ClothNeck"] = 0;
	js["ClothHair"] = 0;
	js["ClothFeet"] = 0;
	js["ClothMask"] = 0;
	js["Level"] = 0;
	js["block"] = 0;
	js["isBanned"] = boolean;
	o << js << std::endl;
}
vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;

void saveAllWorlds() // atexit hack plz fix
{
	cout << "Saving worlds..." << endl;
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	} catch(int e) {
		return NULL;
	}
}

struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;

};


enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	SEED,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	FIST,
	UNKNOWN
};

struct ItemDefinition {
	int id;
	string name;
	int rarity;
	int breakHits;
	int growTime;
	ClothTypes clothType;
	BlockTypes blockType;
	string description = "This item has no description.";
};

vector<ItemDefinition> itemDefs;

struct DroppedItem { // TODO
	int id;
	int uid;
	int count;
};

vector<DroppedItem> droppedItems;

ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return itemDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is tree.";
			}
		}
	}
}

void buildItemsDatabase()
{
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if(bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else {
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (cl == "None") {
				def.clothType = ClothTypes::NONE;
			}
			else if(cl == "Hat") {
				def.clothType = ClothTypes::HAIR;
			}
			else if(cl == "Shirt") {
				def.clothType = ClothTypes::SHIRT;
			}
			else if(cl == "Pants") {
				def.clothType = ClothTypes::PANTS;
			}
			else if (cl == "Feet") {
				def.clothType = ClothTypes::FEET;
			}
			else if (cl == "Face") {
				def.clothType = ClothTypes::FACE;
			}
			else if (cl == "Hand") {
				def.clothType = ClothTypes::HAND;
			}
			else if (cl == "Back") {
				def.clothType = ClothTypes::BACK;
			}
			else if (cl == "Hair") {
				def.clothType = ClothTypes::MASK;
			}
			else if (cl == "Chest") {
				def.clothType = ClothTypes::NECKLACE;
			}
			else {
				def.clothType = ClothTypes::NONE;
			}
			
			if (++current != def.id)
			{
				cout << "Critical error! Unordered database at item "<< std::to_string(current) <<"/"<< std::to_string(def.id) <<"!" << endl;
			}

			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();
}

struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
	long long int lastBC = 0;
	long long int lastVSB = 0;
};

vector<Admin> admins;

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level>1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}

bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level >= 998) {
			return true;
		}
	}
	return false;
}

bool isDev(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level >= 999) {
			return true;
		}
	}
	return false;
}

bool isNormalAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level >= 2) {
			return true;
		}
	}
	return false;
}

bool isVIP(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level >= 0) {
			return true;
		}
	}
	return false;
}

bool isVIPFlag(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1) {
			return true;
		}
	}
	return false;
}

bool isNormalAdminFlag(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 2) {
			return true;
		}
	}
	return false;
}

bool isSuperAdminFlag(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}

bool isDevFlag(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 1000) {
			return true;
		}
	}
	return false;
}

bool isCustomFlag1(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 3) {
			return true;
		}
	}
	return false;
}

bool isCustomFlag2(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 4) {
			return true;
		}
	}
	return false;
}

bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i * 4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket * packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}

BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[56];
	for (int i = 0; i < 56; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);
	memcpy(&dataStruct->netID, data + 4, 4);
	memcpy(&dataStruct->characterState, data + 12, 4);
	memcpy(&dataStruct->plantingTree, data + 20, 4);
	memcpy(&dataStruct->x, data + 24, 4);
	memcpy(&dataStruct->y, data + 28, 4);
	memcpy(&dataStruct->XSpeed, data + 32, 4);
	memcpy(&dataStruct->YSpeed, data + 36, 4);
	memcpy(&dataStruct->punchX, data + 44, 4);
	memcpy(&dataStruct->punchY, data + 48, 4);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void SendPacketRaw(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete packetData;
}


	void onPeerConnect(ENetPeer* peer)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete p.data;
					string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					//enet_host_flush(server);
				}
			}
		}
		
	}

	void updateAllClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), 0.0f, 0.0f, 0.0f));
				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet3);
				delete p3.data;
				//enet_host_flush(server);
				GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), 0.0f, 0.0f, 0.0f));
				memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
				ENetPacket * packet4 = enet_packet_create(p4.data,
					p4.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet4);
				delete p4.data;
				//enet_host_flush(server);
			}
		}
	}

	void sendClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), 0.0f, 0.0f, 0.0f));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{

				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet3);
			}

		}

		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));

			string username = PlayerDB::getProperName(p->rawName);

			std::ifstream od("players/" + username + ".json");
			if (od.is_open()) {
			}

			std::ofstream o("players/" + username + ".json");
			if (!o.is_open()) {
				cout << GetLastError() << endl;
				_getch();
			}
			json j;

			int clothback = p->cloth_back;
			int clothhand = p->cloth_hand;
			int clothface = p->cloth_face;
			int clothhair = p->cloth_hair;
			int clothfeet = p->cloth_feet;
			int clothpants = p->cloth_pants;
			int clothneck = p->cloth_necklace;
			int clothshirt = p->cloth_shirt;
			int clothmask = p->cloth_mask;

			string password = ((PlayerInfo*)(peer->data))->tankIDPass;
			j["username"] = username;
			j["password"] = hashPassword(password);
			j["adminLevel"] = 0;
			j["ClothBack"] = clothback;
			j["ClothHand"] = clothhand;
			j["ClothFace"] = clothface;
			j["ClothShirt"] = clothshirt;
			j["ClothPants"] = clothpants;
			j["ClothNeck"] = clothneck;
			j["ClothHair"] = clothhair;
			j["ClothFeet"] = clothfeet;
			j["ClothMask"] = clothmask;
			j["isBanned"] = "false";

			o << j << std::endl;
		}

		//enet_host_flush(server);
		delete p3.data;
	}
	void sendPData(ENetPeer* peer, PlayerMoving* data)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					data->netID = ((PlayerInfo*)(peer->data))->netID;

					SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
				}
			}
		}
	}

	int getPlayersCountInWorld(string name)
	{
		int count = 0;
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
				count++;
		}
		return count;
	}

	void sendRoulete(ENetPeer* peer, int x, int y)
	{
		ENetPeer* currentPeer;
		int val = rand() % 37;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "Your number is "+std::to_string(val)+"."), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
			}
				

			//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
		}
	}

	void sendNothingHappened(ENetPeer* peer, int x, int y) {
		PlayerMoving data;
		data.netID = ((PlayerInfo*)(peer->data))->netID;
		data.packetType = 0x8;
		data.plantingTree = 0;
		data.netID = -1;
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	}

	void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
	{
		PlayerMoving data;
		//data.packetType = 0x14;
		data.packetType = 0x3;

		//data.characterState = 0x924; // animation
		data.characterState = 0x0; // animation
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		data.XSpeed = 0;
		data.YSpeed = 0;
		data.netID = causedBy;
		data.plantingTree = tile;

		WorldInfo *world = getPlyersWorld(peer);

		if (world == NULL) return;
		if (x<0 || y<0 || x>world->width || y>world->height) return;
		sendNothingHappened(peer, x, y);
		if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y*world->width)].foreground == 3760)
				return;
			if (tile == 6 || tile == 8 || tile == 3760)
				return;
		}
		if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y*world->width)].foreground == 758)
				sendRoulete(peer, x, y);
			return;
		}
		if (world->name != "ADMIN") 
		{
			if (world->owner != "") 
			{
				if (((PlayerInfo*)(peer->data))->rawName == world->owner) 
				{
					// WE ARE GOOD TO GO
					if (tile == 32) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wShould this world be publicly breakable?``|left|242|\n\nadd_spacer|small|\nadd_button_with_icon|worldPublic|Public|noflags|2408||\nadd_button_with_icon|worldPrivate|Private|noflags|202||\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				else if (world->isPublic)
				{
					if (world->items[x + (y*world->width)].foreground == 242)
					{
						return;
					}
					if (world->items[x + (y*world->width)].foreground == 1796)
					{
						return;
					}
				}
				else 
				{
					return;
				}
				if (tile == 242) {
					return;
				}
				if (tile == 1796) {
					return;
				}
			
			}
		}
		if (world->name == "TEST")
		{
			// WE ARE GOOD TO GO
			if (tile == 32)
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard``|left|1790|\nadd_textbox|`oGreetings, Traveler! I am the Legendary Wizard. Should to embark on a Legendary Quest, Simply choose one below.\nadd_spacer|small|\nadd_button|ltitle|Quest for Honor|noflags|0|0|\nadd_button|ldrag|Quest for Fire|noflags|0|0|\nadd_button|lbot|Quest Of Steel|noflags|0|0|\nadd_button|ltitle|Quest Of The Heavens|noflags|0|0|\nnend_dialog|gazette||OK|"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;
			}
		}
		/*else if (world->name = "LEGEND")
		{
			if (tile == 32) 
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard``|left|1790|\nadd_textbox|`oGreetings, Traveler! I am the Legendary Wizard. Should to embark on a Legendary Quest, Simply choose one below.\nadd_spacer|small|\nadd_button|ltitle|Quest for Honor|noflags|0|0|\nadd_button|ldrag|Quest for Fire|noflags|0|0|\nadd_button|lbot|Quest Of Steel|noflags|0|0|\nadd_button|ltitle|Quest Of The Heavens|noflags|0|0|\nnend_dialog|gazette||OK|"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;
			}
		}*/
		/*if (world->name = "LEGEND") 
		{
				if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
					// WE ARE GOOD TO GO
					if (tile == 32) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard``|left|1790|\nadd_textbox|`oGreetings, Traveler! I am the Legendary Wizard. Should to embark on a Legendary Quest, Simply choose one below.\nadd_spacer|small|\nadd_button|ltitle|Quest for Honor|noflags|0|0|\nadd_button|ldrag|Quest for Fire|noflags|0|0|\nadd_button|lbot|Quest Of Steel|noflags|0|0|\nadd_button|ltitle|Quest Of The Heavens|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				else if (world->isPublic)
				{
					if (world->items[x + (y*world->width)].foreground == 1790)
					{
						return;
					}
				}
				else {
					return;
				}
				if (tile == 1790) {
					return;
				}
		}*/
		if (tile == 32) {
			// TODO
			return;
		}
		if (tile == 822) {
			world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
			return;
		}
		if (tile == 3062)
		{
			world->items[x + (y*world->width)].fire = !world->items[x + (y*world->width)].fire;
			return;
		}
		if (tile == 1866)
		{
			world->items[x + (y*world->width)].glue = !world->items[x + (y*world->width)].glue;
			return;
		}
		ItemDefinition def;
		try {
			def = getItemDef(tile);
			if (def.clothType != ClothTypes::NONE) return;
		}
		catch (int e) {
			def.breakHits = 4;
			def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
			cout << "Ugh, unsupported item " << tile << endl;
#endif
		}

		if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile==2994 || tile==4368) return;
		if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
		if(tile == 1902 || tile == 1508 || tile == 428) return;
		if (tile == 410 || tile == 1770 || tile == 4720 || tile == 4882 || tile == 6392 || tile == 3212 || tile == 1832 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
		if (tile >= 7068) return;
		if (tile == 0 || tile == 18) {
			//data.netID = -1;
			data.packetType = 0x8;
			data.plantingTree = 4;
			using namespace std::chrono;
			//if (world->items[x + (y*world->width)].foreground == 0) return;
			if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y*world->width)].breakTime >= 4000)
			{
				world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				world->items[x + (y*world->width)].breakLevel = 4; // TODO
				if (world->items[x + (y*world->width)].foreground == 758)
					sendRoulete(peer, x, y);
			}
			else
				if (y < world->height && world->items[x + (y*world->width)].breakLevel + 4 >= def.breakHits * 4) { // TODO
					data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
					data.netID = -1;
					data.plantingTree = 0;
					world->items[x + (y*world->width)].breakLevel = 0;
					if (world->items[x + (y*world->width)].foreground != 0)
					{
						if (world->items[x + (y*world->width)].foreground == 242)
						{
							world->owner = "";
							world->isPublic = false;
						}
						if (world->items[x + (y*world->width)].foreground == 1796)
						{
							world->owner = "";
							world->isPublic = false;
						}
						world->items[x + (y*world->width)].foreground = 0;
					}
					else {
						world->items[x + (y*world->width)].background = 0;
					}
					
				}
				else
					if (y < world->height)
					{
						world->items[x + (y*world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						world->items[x + (y*world->width)].breakLevel += 4; // TODO
						if (world->items[x + (y*world->width)].foreground == 758)
							sendRoulete(peer, x, y);
					}

		}
		else {
			for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
			{
				if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
				{
					if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > 1)
					{
						((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount--;
					}
					else {
						((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);

					}
				}
			}
			if (def.blockType == BlockTypes::BACKGROUND)
			{
				world->items[x + (y*world->width)].background = tile;
			}
			else 
			{
				world->items[x + (y*world->width)].foreground = tile;
				if (tile == 242) 
				{
					world->owner = ((PlayerInfo*)(peer->data))->rawName;
					world->isPublic = false;
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `2" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete p.data;
						}
					}
				}
				else if (tile == 1796)
				{
					world->owner = ((PlayerInfo*)(peer->data))->rawName;
					world->isPublic = false;
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[`w" + world->name + " `ohas been World Locked by `2" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete p.data;
						}
					}
				}
			}

			world->items[x + (y*world->width)].breakLevel = 0;
		}

		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			
			//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
		}
	}

	void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
	{
		ENetPeer * currentPeer;
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`` left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`` others here>``"));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				{
					
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					
				}
				{
					
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					
				}
			}
		}
		delete p.data;
		delete p2.data;
	}

	/*if (isVIPFlag(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0)
		{
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<" + name + "`o> " + message));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<" + name + "`o> " + message));
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}*/
	void sendChatMessage(ENetPeer* peer, int netID, string message)
	{
		if (message.length() == 0) return;
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->netID == netID)
				name = ((PlayerInfo*)(currentPeer->data))->displayName;

		}
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o> `w" + message));
		GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{

				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet);

				//enet_host_flush(server);

				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);

				//enet_host_flush(server);
			}
		}
		delete p.data;
		delete p2.data;
	}

	void sendWho(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(currentPeer->data))->netID), ((PlayerInfo*)(currentPeer->data))->displayName), 1));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet2);
				delete p2.data;
				//enet_host_flush(server);
			}
		}
	}

	void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
	{
#ifdef TOTAL_LOG
		cout << "Entering a world..." << endl;
#endif
		((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
		string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
		string worldName = worldInfo->name;
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
		int square = xSize * ySize;
		__int16 nameLen = worldName.length();
		int payloadLen = asdf.length() / 2;
		int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8) + 4;
		int allocMem = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 16000;
		BYTE* data = new BYTE[allocMem];
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(data + (i / 2), &x, 1);
		}
		int zero = 0;
		__int16 item = 0;
		int smth = 0;
		for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
		for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
		memcpy(data + payloadLen, &nameLen, 2);
		memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
		memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
		memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
		memcpy(data + payloadLen + 10 + nameLen, &square, 4);
		BYTE* blockPtr = data + payloadLen + 14 + nameLen;
		for (int i = 0; i < square; i++) {
			if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100)/* || (worldInfo->items[i].foreground%2)*/)
			{
				memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
				int type = 0x00000000;
				// type 1 = locked
				if (worldInfo->items[i].water)
					type |= 0x04000000;
				if (worldInfo->items[i].glue)
					type |= 0x08000000;
				if (worldInfo->items[i].fire)
					type |= 0x10000000;
				if (worldInfo->items[i].red)
					type |= 0x20000000;
				if (worldInfo->items[i].green)
					type |= 0x40000000;
				if (worldInfo->items[i].blue)
					type |= 0x80000000;

				// int type = 0x04000000; = water
				// int type = 0x08000000 = glue
				// int type = 0x10000000; = fire
				// int type = 0x20000000; = red color
				// int type = 0x40000000; = green color
				// int type = 0x80000000; = blue color
				memcpy(blockPtr + 4, &type, 4);
				/*if (worldInfo->items[i].foreground % 2)
				{
					blockPtr += 6;
				}*/
			}
			else
			{
				memcpy(blockPtr, &zero, 2);
			}
			memcpy(blockPtr + 2, &worldInfo->items[i].background, 2);
			blockPtr += 8;
			/*if (blockPtr - data < allocMem - 2000) // realloc
			{
				int wLen = blockPtr - data;
				BYTE* oldData = data;

				data = new BYTE[allocMem + 16000];
				memcpy(data, oldData, allocMem);
				allocMem += 16000;
				delete oldData;
				blockPtr = data + wLen;

			}*/
		}
		memcpy(data + dataLen - 4, &smth, 4);
		ENetPacket * packet2 = enet_packet_create(data,
			dataLen,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet2);
		//enet_host_flush(server);
		for (int i = 0; i < square; i++) {
			if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100))
				; // nothing
			else
			{
				PlayerMoving data;
				//data.packetType = 0x14;
				data.packetType = 0x3;

				//data.characterState = 0x924; // animation
				data.characterState = 0x0; // animation
				data.x = i % worldInfo->width;
				data.y = i / worldInfo->height;
				data.punchX = i % worldInfo->width;
				data.punchY = i / worldInfo->width;
				data.XSpeed = 0;
				data.YSpeed = 0;
				data.netID = -1;
				data.plantingTree = worldInfo->items[i].foreground;
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;

		if (((PlayerInfo*)(peer->data))->haveGrowId) {

			PlayerInfo* p = ((PlayerInfo*)(peer->data));
			std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
			json j;
			ifff >> j;

			p->currentWorld = worldInfo->name;

			int bac, han, fac, hai, fee, pan, nec, shi, mas;
			bac = j["ClothBack"];
			han = j["ClothHand"];
			fac = j["ClothFace"];
			hai = j["ClothHair"];
			fee = j["ClothFeet"];
			pan = j["ClothPants"];
			nec = j["ClothNeck"];
			shi = j["ClothShirt"];
			mas = j["ClothMask"];

			p->cloth_back = bac;
			p->cloth_hand = han;
			p->cloth_face = fac;
			p->cloth_hair = hai;
			p->cloth_feet = fee;
			p->cloth_pants = pan;
			p->cloth_necklace = nec;
			p->cloth_shirt = shi;
			p->cloth_mask = mas;

			sendClothes(peer);

			ifff.close();

		}

		delete data;

	}

	void sendAction(ENetPeer* peer, int netID, string action)
	{
		ENetPeer * currentPeer;
		string name = "";
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnAction"), action));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				
				memcpy(p2.data + 8, &netID, 4);
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);
				
				//enet_host_flush(server);
			}
		}
		delete p2.data;
	}


	// droping items WorldObjectMap::HandlePacket
	void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
	{
		if (item >= 7068) return;
		if (item < 0) return;
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 14;
				data.x = x;
				data.y = y;
				data.netID = netID;
				data.plantingTree = item;
				float val = count; // item count
				BYTE val2 = specialEffect;

				BYTE* raw = packPlayerMoving(&data);
				memcpy(raw + 16, &val, 4);
				memcpy(raw + 1, &val2, 1);

				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}

	void sendState(ENetPeer* peer) {
		//return; // TODO
		PlayerInfo* info = ((PlayerInfo*)(peer->data));
		int netID = info->netID;
		ENetPeer * currentPeer;
		int state = getState(info);
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 0x14;
				data.characterState = 0; // animation
				data.x = 1000;
				data.y = 100;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 300;
				data.YSpeed = 600;
				data.netID = netID;
				data.plantingTree = state;
				BYTE* raw = packPlayerMoving(&data);
				int var = 0x808000; // placing and breking
				memcpy(raw+1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		// TODO
	}

	

	void sendWorldOffers(ENetPeer* peer)
	{
		if (!((PlayerInfo*)(peer->data))->isIn) return;
		vector<WorldInfo> worlds = worldDB.getRandomWorlds();
		string worldOffers = "default|";
		if (worlds.size() > 0) {
			worldOffers += worlds[0].name;
		}
		
		worldOffers += "\nadd_button|Showing: `wBest Worlds``|_catselect_|0.6|3529161471|\n";
		for (int i = 0; i < worlds.size(); i++) {
			worldOffers += "add_floater|"+worlds[i].name+"|"+std::to_string(getPlayersCountInWorld(worlds[i].name))+"|0.55|3529161471\n";
		}
		//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
		//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));
		ENetPacket * packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet3);
		delete p3.data;
		//enet_host_flush(server);
	}





	BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
	{
		saveAllWorlds();
		return FALSE;
	}

	/*
	action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
int _tmain(int argc, _TCHAR* argv[])
{
	cout << "Growtopia private server (c) Growtopia Noobs" << endl;
	enet_initialize();
	if (atexit(saveAllWorlds)) {
		cout << "Worlds won't be saved for this session..." << endl;
	}
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
		cout << "Autorestart is ready" << endl;
	}
	else {
		cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	SetConsoleCtrlHandler(HandlerRoutine, true);
	
	// load items.dat
	{
		std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
		itemsDatSize = file.tellg();

	
		itemsDat = new BYTE[60 + itemsDatSize];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &itemsDatSize, 4);
		file.seekg(0, std::ios::beg);

		if (file.read((char*)(itemsDat + 60), itemsDatSize))
		{
			cout << "Updating items data suecess!" << endl;

		}
		else {
			cout << "Updating items data failed!" << endl;
		}
	}
	//for example you should write like this other them addAdmin("username", "password", adminlvl); under of them vip - 1 mod - 2 admin - 999 dev - 1000
	addAdmin("username", "password", 999);//fortesting ;)

	//world = generateWorld();
	worldDB.get("TEST");
	worldDB.get("MAIN");
	worldDB.get("NEW");
	//worldDB.get("ADMIN");
	worldDB.get("LEGEND");
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host (&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = 17091;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	cout << "Building items database..." << endl;
	buildItemsDatabase();
	cout << "Database is built!" << endl;

	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true)
	while (enet_host_service(server, &event, 1000) > 0)
	{
		ENetPeer* peer = event.peer;
		switch (event.type)
		{
		case ENET_EVENT_TYPE_CONNECT:
		{
#ifdef TOTAL_LOG
			printf("A new client connected.\n");
#endif
			/* Store any relevant client information here. */
			//event.peer->data = "Client information";
			ENetPeer * currentPeer;
			int count = 0;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer->address.host == peer->address.host)
					count++;
			}

			event.peer->data = new PlayerInfo;
			if (count > 3)
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rToo much accounts are logged on from this IP. If you don't think so, then please let server relax and connect again in half minute or so.``"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
				enet_peer_disconnect_later(peer, 0);
			}
			else {
				sendData(peer, 1, 0, 0);
			}


			continue;
		}
		case ENET_EVENT_TYPE_RECEIVE:
		{
			if (((PlayerInfo*)(peer->data))->isUpdating)
			{
				cout << "packet drop" << endl;
				continue;
			}
			/*printf("A packet of length %u containing %s was received from %s on channel %u.\n",
				event.packet->dataLength,
				event.packet->data,
				event.peer->data,
				event.channelID);
			cout << (int)*event.packet->data << endl;*/
			//cout << text_encode(getPacketData((char*)event.packet->data));
			/*for (int i = 0; i < event.packet->dataLength; i++)
			{
				cout << event.packet->data[i];
			}
			sendData(7, 0, 0);
			string x = "eventType|0\neventName|102_PLAYER.AUTHENTICATION\nAuthenticated|0\nAuthentication_error|6\nDevice_Id|^^\nGrow_Id|0\nName|^^Elektronik\nWordlock_balance|0\n";
			//string x = "eventType | 0\neventName | 102_PLAYER.AUTHENTICATION\nAuthenticated | 0\nAuthentication_error | 6\nDevice_Id | ^^\nGrow_Id | 0\nName | ^^Elektronik\nWorldlock_balance | 0\n";
			sendData(6, (char*)x.c_str(), x.length());
			string y = "action|quit\n";
			sendData(3, (char*)y.c_str(), y.length());
			cout << endl;
			string asdf = "0400000001000000FFFFFFFF0000000008000000000000000000000000000000000000000000000000000000000000000000000000000000400000000600020E0000004F6E53656E64546F5365727665720109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
			//asdf = "0400000001000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000040000000060002220000004F6E53757065724D61696E53746172744163636570744C6F676F6E464232313131330109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
			ENetPacket * packet = enet_packet_create(0,
				asdf.length()/2,
				ENET_PACKET_FLAG_RELIABLE);
			for (int i = 0; i < asdf.length(); i += 2)
			{
				char x = ch2n(asdf[i]);
				x = x << 4;
				x += ch2n(asdf[i + 1]);
				memcpy(packet->data + (i / 2), &x, 1);
			}
			enet_peer_send(peer, 0, packet);
			enet_host_flush(server);
			/* Clean up the packet now that we're done using it. */
			//enet_packet_destroy(event.packet);
			//sendData(7, 0, 0);
			int messageType = GetMessageTypeFromPacket(event.packet);
			//cout << "Packet type is " << messageType << endl;
			//cout << (event->packet->data+4) << endl;
			WorldInfo* world = getPlyersWorld(peer);
			switch (messageType) {
			case 2:
			{
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				string cch = GetTextPointerFromPacket(event.packet);
				string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
				if (cch.find("action|respawn") == 0)
				{
					int x = 3040;
					int y = 736;

					if (!world) continue;

					for (int i = 0; i < world->width*world->height; i++)
					{
						if (world->items[i].foreground == 6) {
							x = (i%world->width) * 32;
							y = (i / world->width) * 32;
						}
					}
					{
						PlayerMoving data;
						data.packetType = 0x0;
						data.characterState = 0x924; // animation
						data.x = x;
						data.y = y;
						data.punchX = -1;
						data.punchY = -1;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0x0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}

					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSpawn"), 0));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
#ifdef TOTAL_LOG
					cout << "Respawning... " << endl;
#endif
				}
				if (cch.find("action|growid") == 0)
				{
#ifndef REGISTRATION
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Registration is not supported yet!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
#endif
#ifdef REGISTRATION
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet your GrowID Now!``|left|32|\n\nadd_spacer|small|\nadd_text_input|username|GrowID: ||15|\nadd_text_input|password|Password: ||100|\nend_dialog|register|Cancel|OK|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						enet_host_flush(server);
						delete p.data;
#endif
				}
				if (cch.find("action|store") == 0)
				{
					PlayerInventory inventory;
					((PlayerInfo*)(event.peer->data))->inventory = inventory;
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrowtopia Store   ``|left|1796|\n\nadd_spacer|small|\n\nadd_textbox|`7Name : `w" + name + "|left|\n\nadd_textbox|`oIf you want in-game admin, vip or etc roles that higher than members you can buy for Growtopia DLS|left|\n\nadd_spacer|small|\nadd_url_button||`1Discord server!|NOFLAGS|https://discord.gg/kkZtp3Q|Open link?\n\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					/*GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``!  Tap the item you'd like more info on.`o  `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nadd_button|iap_menu|Buy Gems|interface/large/store_buttons5.rttex||0|2|0|0||\nadd_button|subs_menu|Subscriptions|interface/large/store_buttons22.rttex||0|1|0|0||\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|Weather Machines|interface/large/store_buttons5.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|4|0|0||\n"));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2);
					delete p2.data;*/
					//enet_host_flush(server);
				}
				//if (cch.find("action|logmsg") == | `4UPDATE REQUIRED!`` : The `oV2.981`` update is now available for your device.Go get it!You'll need to install it before you can play online.[DBG] Some text is here: action|set_urlurl|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exelabel|Download Latest Version
				/*if (cch.find("action|store") == 0)
				{
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``!  Tap the item you'd like more info on.`o  `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nadd_button|iap_menu|Buy Gems|interface/large/store_buttons5.rttex||0|2|0|0||\nadd_button|subs_menu|Subscriptions|interface/large/store_buttons22.rttex||0|1|0|0||\nadd_button|token_menu|Growtoken Items|interface/large/store_buttons9.rttex||0|0|0|0||\nadd_button|pristine_forceps|`oAnomalizing Pristine Bonesaw``|interface/large/store_buttons20.rttex|Built to exacting specifications by GrowTech engineers to find and remove temporal anomalies from infected patients, and with even more power than Delicate versions! Note : The fragile anomaly - seeking circuitry in these devices is prone to failure and may break (though with less of a chance than a Delicate version)! Use with care!|0|3|3500|0||\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons16.rttex|`2September 2018:`` `9Sorcerer's Tunic of Mystery!`` Capable of reflecting the true colors of the world around it, this rare tunic is made of captured starlight and aether. If you think knitting with thread is hard, just try doing it with moonbeams and magic! The result is worth it though, as these clothes won't just make you look amazing - you'll be able to channel their inherent power into blasts of cosmic energy!``|0|3|200000|0||\nadd_button|contact_lenses|`oContact Lens Pack``|interface/large/store_buttons22.rttex|Need a colorful new look? This pack includes 10 random Contact Lens colors (and may include Contact Lens Cleaning Solution, to return to your natural eye color)!|0|7|15000|0||\nadd_button|locks_menu|Locks And Stuff|interface/large/store_buttons3.rttex||0|4|0|0||\nadd_button|itempack_menu|Item Packs|interface/large/store_buttons3.rttex||0|3|0|0||\nadd_button|bigitems_menu|Awesome Items|interface/large/store_buttons4.rttex||0|6|0|0||\nadd_button|weather_menu|Weather Machines|interface/large/store_buttons5.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|4|0|0||\n"));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					//enet_host_flush(server);
				}*/
				//if (cch.find("action|logmsg") == | `4UPDATE REQUIRED!`` : The `oV2.981`` update is now available for your device.Go get it!You'll need to install it before you can play online.[DBG] Some text is here: action|set_urlurl|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exelabel|Download Latest Version
				if (cch.find("action|help") == 0)
				{
					PlayerInventory inventory;
					((PlayerInfo*)(event.peer->data))->inventory = inventory;
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPlayers Helper   ``|left|1796|\n\nadd_spacer|small|\n\nadd_textbox|`7Name : `w" + name + "|left|\n\nadd_textbox|`oDo you need helps!?|left|\n\nadd_spacer|small|\nadd_url_button||`1Discord can help you!|NOFLAGS|https://discord.gg/kkZtp3Q|Open link?\n\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				if (cch.find("action|friends") == 0)
				{
					PlayerInventory inventory;
					((PlayerInfo*)(event.peer->data))->inventory = inventory;
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wSocial Portal``|left|interface/large/friend_button.rttex|0|0|\nadd_spacer|small|\nadd_button|chc0|Show Friends|noflags|0|0|\nadd_button|chc0|Create Guild|noflags|0|0|\nadd_spacer|small||30|\nadd_button|chc0|OK|noflags|0|0|\nnend_dialog|gazette||`yOK|"));//friend_button gazette
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				if (cch.find("action|wrench") == 0)
				{
					PlayerInventory inventory;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					((PlayerInfo*)(event.peer->data))->inventory = inventory;
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + name + "``     `w(`2?`w)|left|18|\nadd_spacer|small|\nadd_button|chc0|Trade|noflags|0|0|\nadd_button|chc0|Freeze|noflags|0|0|\nadd_button|chc0|Punish/View|noflags|0|0|\nadd_button|chc0|Add as friend|noflags|0|0|\nadd_spacer|small|\nadd_button|chc0|Continue|noflags|0|0|\nnend_dialog|gazette||`yOK|"));//friend_button gazette
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				if (cch.find("action|event") == 0)
				{

					PlayerInventory inventory;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					((PlayerInfo*)(event.peer->data))->inventory = inventory;
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`7Summer Clash Event Has Ended!|left|836|\nadd_textbox|Summer Clash has ended, but worry not - a new Season Clash is comming soon!|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||`yOK|"));//friend_button
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				if (cch.find("action|info") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					int id = -1;
					int count = -1;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 3) {
							if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
							if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
						}
					}
					if (id == -1 || count == -1) continue;
					if (itemDefs.size() < id || id < 0) continue;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
				}
				if (cch.find("action|dialog_return") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					string btn = "";
					bool isRegisterDialog = false;
					string username = "";
					string password = "";
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 2) {
							if (infoDat[0] == "buttonClicked") btn = infoDat[1];
							if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
							{
								isRegisterDialog = true;
							}
							if (isRegisterDialog) {
								if (infoDat[0] == "username") username = infoDat[1];
								if (infoDat[0] == "password") password = infoDat[1];
							}
						}
					}
					if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
					if(btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
					if (btn == "On")
					{
						((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
						((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
						sendState(peer);
					}
					if (btn == "Off")
					{
						((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
						((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
						sendState(peer);
					}
					if (btn == "ldrag")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 1782;
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "/interface/particle/explosion.rttex"));
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnParticleEffectV2"), "/interface/particle/explosion.rttex"));
						ENetPacket * packet = enet_packet_create(p.data,p.len,ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						delete p.data;
					}
					if (btn == "lwings")
					{
						((PlayerInfo*)(peer->data))->cloth_back = 1784;
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "/interface/particle/explosion.rttex"));
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnParticleEffectV2"), "/interface/particle/explosion.rttex"));
						ENetPacket * packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						delete p.data;
					}
					if (btn == "lbot")
					{
						((PlayerInfo*)(peer->data))->cloth_shirt = 1780;
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "/interface/particle/explosion.rttex"));
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnParticleEffectV2"), "/interface/particle/explosion.rttex"));
						ENetPacket * packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						delete p.data;
					}
					if (btn == "lwhip")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 6026;
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "/interface/particle/explosion.rttex"));
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnParticleEffectV2"), "/interface/particle/explosion.rttex"));
						ENetPacket * packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						delete p.data;
					}
					if (btn == "lkat")
					{
						((PlayerInfo*)(peer->data))->cloth_hand = 2592;
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "/interface/particle/explosion.rttex"));
						GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnParticleEffectV2"), "/interface/particle/explosion.rttex"));
						ENetPacket * packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						delete p.data;
					}
#ifdef REGISTRATION
					if (isRegisterDialog) {

						int regState = PlayerDB::playerRegister(username, password);
						if (regState == 1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rYour account was created!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), 1), username), password));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);

							//enet_host_flush(server);
							delete p2.data;
							enet_peer_disconnect_later(peer, 0);
						}
						else if(regState==-1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rCreation of account failed, because it already exists!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -2) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rCreation of account failed, because name is too short!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
#endif
				}
				string dropText = "action|drop\n|itemID|";
				if (cch.find(dropText) == 0)
				{
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft?-1:1)), ((PlayerInfo*)(peer->data))->y, atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str()), 1, 0);
					/*int itemID = atoi(cch.substr(dropText.length(), cch.length() - dropText.length() - 1).c_str());
					PlayerMoving data;
					data.packetType = 14;
					data.x = ((PlayerInfo*)(peer->data))->x;
					data.y = ((PlayerInfo*)(peer->data))->y;
					data.netID = -1;
					data.plantingTree = itemID;
					float val = 1; // item count
					BYTE val2 = 0; // if 8, then geiger effect
					
					BYTE* raw = packPlayerMoving(&data);
					memcpy(raw + 16, &val, 4);
					memcpy(raw + 1, &val2, 1);
					SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
				}
				if (cch.find("text|") != std::string::npos){
					if (str == "/mod")
					{
						PlayerInventory inventory;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(event.peer->data))->inventory = inventory;
						{
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`2Moderator Noclip``|left|5956|\nadd_spacer|small|\nadd_button|On|On|noflags|0|0|small|\nadd_button|Off|Off|noflags|0|0|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||`yOK|"));//friend_button gazette
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}
					else if (str.substr(0, 7) == "/state ")
					{
						PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 0;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}
					else if (str == "/unequip")
					{
						((PlayerInfo*)(peer->data))->cloth_hair = 0;
						((PlayerInfo*)(peer->data))->cloth_shirt = 0;
						((PlayerInfo*)(peer->data))->cloth_pants = 0;
						((PlayerInfo*)(peer->data))->cloth_feet = 0;
						((PlayerInfo*)(peer->data))->cloth_face = 0;
						((PlayerInfo*)(peer->data))->cloth_hand = 0;
						((PlayerInfo*)(peer->data))->cloth_back = 0;
						((PlayerInfo*)(peer->data))->cloth_mask = 0;
						((PlayerInfo*)(peer->data))->cloth_necklace = 0;
						sendClothes(peer);
					}
					else if (str.substr(0, 5) == "/ban ") {
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancients `ohave used `#Ban `oon `0" + str.substr(5, cch.length() - 5 - 1) + "`o! `#**"));
							ENetPacket * packetba = enet_packet_create(ban.data,
								ban.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packetba);
							}
							if (str.substr(7, cch.length() - 7 - 1) == "") continue;
							string username = PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1));
							unbangay("true", username);
							enet_host_flush(server);
							delete ban.data;


						}

					}
					else if (str == "/help") {
						GamePacket p = packetEnd(appendString(appendString(appendString(createPacket(), "OnConsoleMessage"), "Supported commands are: /help, /mod, /inventory, /item id, /team id, /color number, /who, /state number, /count, /sb message, /alt, /radio, /ah, /gems amount, /vweather id, /unequip"), "audio/beep.wav"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/vhelp") {
						GamePacket p = packetEnd(appendString(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9VIP Commands `o: /vnick /nick /vsb /find"), "audio/beep.wav"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/mhelp") {
						GamePacket p = packetEnd(appendString(appendString(appendString(createPacket(), "OnConsoleMessage"), "`bModerator Commands `o: /vnick /mnick /nick /vsb /msb /find /pull /ah"), "audio/beep.wav"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/?") {
						GamePacket p = packetEnd(appendString(appendString(appendString(createPacket(), "OnConsoleMessage"), "Supported commands are: /help, /mod, /inventory, /item id, /team id, /color number, /who, /state number, /count, /sb message, /alt, /radio, /ah, /gems amount, /vweather id, /unequip"), "audio/beep.wav"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/legend")
					{
				
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard``|left|1790|\nadd_textbox|`oGreetings, Traveler! I am the Legendary Wizard. Should to embark on a Legendary Quest, Simply choose one below.|left|\nadd_spacer|small|\nadd_button|ltitle|Quest for Honor|noflags|0|0|\nadd_button|ldrag|Quest for Fire|noflags|0|0|\nadd_button|lbot|Quest Of Steel|noflags|0|0|\nadd_button|lwings|Quest Of The Heavens|noflags|0|0|\nadd_button|lkat|Quest of Blade|noflags|0|0|\nadd_button|lwhip|Quest for Condour|noflags|0|0|\nadd_spacer|small|\nadd_button|c0co|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								//enet_host_flush(server);
								delete p.data;
					}
					else if (str == "/ah")
					{
						if (!isNormalAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						ENetPeer* currentPeer;
						PlayerInventory inventory;
						((PlayerInfo*)(event.peer->data))->inventory = inventory;
						{
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wAdministrator Help``|left|1796|\n\nadd_spacer|small|\n\nadd_textbox|`7Name : `w" + name + "|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4COMMAND:`` /asb (Admin Super Boardcast)|left|5956|\n\nadd_spacer|small|\nadd_label_with_icon|small|`4COMMAND:`` /reset (Only use when the owner says to)|left|5956|\nadd_label_with_icon|small|`4COMMAND:`` /sdb (Super Duper Boardcast) `4*Disabled ``|left|5956|\nadd_spacer|small|\nadd_label_with_icon|small|`4COMMAND:`` /gsm (Global System Message)|left|5956||0|0|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}
					else if (str.substr(0, 6) == "/gems ")
					{

						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), atoi(str.substr(6).c_str())));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						continue;



					}//string name = ((PlayerInfo*)(peer->data))->displayName;
					else if (str.substr(0, 10) == "/vweather ")
					{
						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(10).c_str())));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						continue;

					}
					else if (str.substr(0, 6) == "/find ") {
						if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						if (str.substr(6, cch.length() - 6 - 1) == "") continue;

						ENetPeer * currentPeer;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Finding user: " + str.substr(6, cch.length() - 6 - 1)));

						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
								GamePacket psp = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "user " + str.substr(6, cch.length() - 6 - 1) + " is located at: " + ((PlayerInfo*)(currentPeer->data))->currentWorld));

								ENetPacket * packetd = enet_packet_create(psp.data,
									psp.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetd);
								delete psp.data;
							}
						}
					}
					/*else if (str == "/find")
					{
						ENetPeer* currentPeer;
						PlayerInventory inventory;
						((PlayerInfo*)(event.peer->data))->inventory = inventory;
						{
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wFind Players``|left|1796|\nadd_spacer|small|\nadd_textbox|Enter a player name below to find item|left|\nadd_textbox|`4Example : `oTo find someone with @, !, #, of Legend or etc that's special alphabet, You should enter that person's name|left|\nadd_text_input|findplayer|Find Player||30|\nadd_button|findplayer|Find player!|noflags|0|0|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}*/
					/*else if (str == "/puncheff")
					{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnParticleEffect"), "Growtopia.exe + 1EAFAF: db 0F 85 DB 01 00 00"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete p.data;
					continue;

					}*/
					//|\nadd_text_input|username|GrowID||30|
					else if (str.substr(0, 7) == "/unban ") {
						{
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
							GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancients `ohave used `#UnBan `oon `0" + str.substr(5, cch.length() - 5 - 1) + "`o! `#**"));
							ENetPacket * packetba = enet_packet_create(ban.data,
								ban.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								enet_peer_send(currentPeer, 0, packetba);
							}
							if (str.substr(7, cch.length() - 7 - 1) == "") continue;
							string username = PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1));
							unbangay("false", username);
							enet_host_flush(server);
							delete ban.data;

						}

					}
					else if (str == "/mods") {

					string mods = "";

					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (isNormalAdmin(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0)
						{
							mods += ((PlayerInfo*)(currentPeer->data))->rawName ==  + " ,";
						}
					}

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Mods online: " + mods));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;

					}
					else if (str.substr(0, 4) == "/bc ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastBC + 20000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastBC = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait a minute before using the bc command again!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}

					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Broadcast`` from `o`2" + name + "```` :`` `# " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket * packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
					}
					else if (str.substr(0, 5) == "/gsm ")
					{
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "GSM from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
					using namespace std::chrono;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Global System Message :`` " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket * packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
					}
					else if (str.substr(0, 6) == "/pull ") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					if (str.substr(6, cch.length() - 6 - 1) == "") continue;

					ENetPeer * currentPeer;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Pulled user: " + str.substr(6, cch.length() - 6 - 1)));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
							if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
							if (((PlayerInfo*)(currentPeer->data))->currentWorld == ((PlayerInfo*)(peer->data))->currentWorld) {
								((PlayerInfo*)(currentPeer->data))->y = ((PlayerInfo*)(peer->data))->y;
								((PlayerInfo*)(currentPeer->data))->x = ((PlayerInfo*)(peer->data))->x;
							}
						}

						enet_peer_send(peer, 0, packet);
					}
					delete p.data;
					}
					/*else if (str.substr(0, 5) == "/ban ")
						{
						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#** `$The Ancients `ohave used `#Ban `oon `0" + str.substr(5, cch.length() - 5 - 1) + "`o! `#**"));
						ENetPacket * packetba = enet_packet_create(ban.data,
							ban.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packetba);
						}

						//enet_host_flush(server);
						delete ban.data;
						}*/
					else if (str == "/fakeban") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << "Fake Ban from " << ((PlayerInfo*)(peer->data))->displayName << endl;
					GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "`wWarning from `4Admin: `wYou've been `4BANNED `wfrom Growtopia for 720 days"), "audio/hub_open.wav"), 0));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					ENetPeer * currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						enet_peer_send(currentPeer, 0, packet);
					}
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str == "/vipnick") {
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << ((PlayerInfo*)(peer->data))->displayName << " nicked into a VIP"<< endl;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);
					string nick = ((PlayerInfo*)(peer->data))->displayName;
					((PlayerInfo*)(peer->data))->displayName = ""+ nick +" <VIP>";

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed! <VIP>"));
					ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/nick ") {
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << ((PlayerInfo*)(peer->data))->displayName << "nicked into " << str.substr(6, cch.length() - 6 - 1) << endl;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);

					((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed!"));
					ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
					}
					else if (str == "/modnick") {
					if (!isNormalAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << ((PlayerInfo*)(peer->data))->displayName << " nicked into a Mod" << endl;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);
					string nick = ((PlayerInfo*)(peer->data))->displayName;
					((PlayerInfo*)(peer->data))->displayName = "" + nick + " <Mod>";

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed! <Mod>"));
					ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
					}
					else if (str == "/adminnick") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << ((PlayerInfo*)(peer->data))->displayName << " nicked into a Mod" << endl;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);
					string nick = ((PlayerInfo*)(peer->data))->displayName;
					((PlayerInfo*)(peer->data))->displayName = "" + nick + " <Admin>";

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed! <Admin>"));
					ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/nick ") {
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					cout << ((PlayerInfo*)(peer->data))->displayName << "nicked into " << str.substr(6, cch.length() - 6 - 1) << endl;
					sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
					((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
					sendWorldOffers(peer);

					((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);

					GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Your nickname has been changed!"));
					ENetPacket * packet = enet_packet_create(ps.data,
						ps.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete ps.data;
					//enet_host_flush(server);
					}
					else if (str == "/invis")
					{
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						//string name = ((PlayerInfo*)(peer->data))->displayName;
						((PlayerInfo*)(peer->data))->displayName = "";
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Invisible mode `2ON"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
						((PlayerInfo*)(event.peer->data))->canWalkInBlocks = true;
						sendClothes(peer);
						((PlayerInfo*)(peer->data))->cloth_face = 0;
						sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
						((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
						sendWorldOffers(peer);
						continue;

					}
					else if (str.substr(0, 10) == "/weather ")
					{
					GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete p.data;
					continue;

					}
					else if (str.substr(0, 6) == "/drop ")
					{

					//rl
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);

					//up lr
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y - 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);

					//down lr

					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 1 : -1)), ((PlayerInfo*)(peer->data))->y + 1, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 2 : -2)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 3 : -3)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 4 : -4)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? 5 : -5)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -2 : 2)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -4 : 4)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -5 : 5)), ((PlayerInfo*)(peer->data))->y + 32, atoi(str.substr(6, cch.length() - 6 - 1).c_str()), 1, 0);
					}
					else if (str == "/count"){
						int count = 0;
						ENetPeer * currentPeer;
						string name = "";
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							count++;
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "There is "+std::to_string(count)+" people out of 1024 limit."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 5) == "/asb "){
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "ASB from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/hub_open.wav"), 0));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 4) == "/id ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->lastSB + 10000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming id too fast, calm down."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}

					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `bItems ID`` from `$`2" + name + "```` ** :`` `9 " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket * packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
					}
					else if (str.substr(0, 4) == "/sb ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming sb too fast, calm down."));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}

						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer * currentPeer;
						
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);
							
							
							
							
							ENetPacket * packet2 = enet_packet_create(data,
								5+text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							
							//enet_host_flush(server);
						}
						delete data;
						delete p.data;
					}
					else if (str.substr(0, 5) == "/msb ") {
					using namespace std::chrono;
					if (!isNormalAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `rModerator-Broadcast`` from `$`2" + name + "```` (in `4HIDDEN!``) ** :`` `6 " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket * packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
					}
					else if (str.substr(0, 5) == "/vsb ") {
					using namespace std::chrono;
					/*if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are spamming sb too fast, calm down."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
						continue;
					}*/
					if (((PlayerInfo*)(peer->data))->lastVSB + 10000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						((PlayerInfo*)(peer->data))->lastVSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					if (!isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `9VIP-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `6 " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer * currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket * packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
					}
					else if (str.substr(0, 6) == "/radio") {
						GamePacket p;
						if (((PlayerInfo*)(peer->data))->radio) {
							p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You now won't recieve broadcast anymore."));
							((PlayerInfo*)(peer->data))->radio = false;
						} else {
							p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You will now recieve broadcasts again."));
							((PlayerInfo*)(peer->data))->radio = true;
						}

						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/reset"){
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						//enet_host_flush(server);
					}

					/*else if (str.substr(0, 7) == "/clear "){
						if (!canClear(((PlayerInfo*)(peer->data))->
						rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
						WorldInfo* wrld = getPlyersWorld(peer);
						string wName = str.substr(4, cch.length() - 4 - 1);
						for (auto & c : wName) c = toupper(c);
						for (int i = 0; i < wrld.size(); i++)
						{
							if (wrld == NULL) continue;
							if (wName == wrld->name)
							{
								worlds.at(i) = generateWorld(wrld->name, wrld->width, wrld->height);
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
									{
										sendWorld(currentPeer, &worlds.at(i));

										int x = 3040;
										int y = 736;

										for (int j = 0; j < worlds.at(i).width*worlds.at(i).height; j++)
										{
											if (worlds.at(i).items[j].foreground == 6) {
												x = (j%worlds.at(i).width) * 32;
												y = (j / worlds.at(i).width) * 32;
											}
										}
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
										//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										
										enet_host_flush(server);
										delete p.data;
										((PlayerInfo*)(currentPeer->data))->netID = cId;
										onPeerConnect(currentPeer);
										cId++;

										sendInventory(((PlayerInfo*)(event.peer->data))->inventory);
									}

								}
								enet_host_flush(server);
							}
						}
					}*/
					/*else if (str.substr(0, 6) == "/clear"){
						if (!canClear(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
						WorldInfo* wrld = getPlyersWorld(peer);
						for (int i = 0; i < worlds.size(); i++)
						{
							if (wrld == NULL) continue;
							if (&worlds.at(i) == wrld)
							{
								worlds.at(i) = generateWorld(wrld->name, wrld->width, wrld->height);
								ENetPeer * currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
									{
										sendWorld(currentPeer, &worlds.at(i));

										int x = 3040;
										int y = 736;

										for (int j = 0; j < worlds.at(i).width*worlds.at(i).height; j++)
										{
											if (worlds.at(i).items[j].foreground == 6) {
												x = (j%worlds.at(i).width) * 32;
												y = (j / worlds.at(i).width) * 32;
											}
										}
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
										//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										
										enet_host_flush(server);
										delete p.data;
										((PlayerInfo*)(currentPeer->data))->netID = cId;
										onPeerConnect(currentPeer);
										cId++;

										sendInventory(((PlayerInfo*)(event.peer->data))->inventory);
									}
										
								}
								enet_host_flush(server);
							}
						}
					}*/
					else if (str == "/unmod")
					{
						((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
						sendState(peer);
						/*PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 1;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0x0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
					}
					else if (str == "/alt") {
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
						ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					else
					if (str == "/inventory")
					{
						sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
					} else
					if (str.substr(0,6) == "/item ")
					{
						PlayerInventory inventory;
						InventoryItem item;
						item.itemID = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						item.itemCount = 200;
						inventory.items.push_back(item);
						item.itemCount = 1;
						item.itemID = 18;
						inventory.items.push_back(item);
						item.itemID = 32;
						inventory.items.push_back(item);
						sendInventory(peer, inventory);
					} else
					if (str.substr(0, 6) == "/team ")
					{
						int val = 0;
						val = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						PlayerMoving data;
						//data.packetType = 0x14;
						data.packetType = 0x1B;
						//data.characterState = 0x924; // animation
						data.characterState = 0x0; // animation
						data.x = 0;
						data.y = 0;
						data.punchX = val;
						data.punchY = 0;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

					} else 
					if (str.substr(0, 7) == "/color ")
					{
						((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						sendClothes(peer);
					}
					if (str.substr(0, 4) == "/who")
					{
						sendWho(peer);

					}
					if (str.length() && str[0] == '/')
					{
						sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
					} else if (str.length()>0)
					{
						sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
					}
					
			}
			if (!((PlayerInfo*)(event.peer->data))->isIn)
			{
				
				GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), -703607114), "cdn.growtopiagame.com"), "cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=42|choosemusic=audio/mp3/about_theme.mp3|active_holiday=0|"));
				//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					
					//enet_host_flush(server);
					delete p.data;
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					while (std::getline(ss, to, '\n')){
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "tankIDName")
						{
							((PlayerInfo*)(event.peer->data))->tankIDName = act;
							((PlayerInfo*)(event.peer->data))->haveGrowId = true;
						}
						else if(id == "tankIDPass")
						{
							((PlayerInfo*)(event.peer->data))->tankIDPass = act;
						}
						else if(id == "requestedName")
						{
							((PlayerInfo*)(event.peer->data))->requestedName = act;
						}
						else if (id == "country")
						{
							((PlayerInfo*)(event.peer->data))->country = act;
						}
					}
					if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
					{
						((PlayerInfo*)(event.peer->data))->rawName = "";
						((PlayerInfo*)(event.peer->data))->displayName = "`4Not Registered_`w" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length()>15?15:((PlayerInfo*)(event.peer->data))->requestedName.length()));
					}
					else {
						((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
						int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
						if (logStatus == -3) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are banned from Growtopia Private Server!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							enet_peer_disconnect_later(peer, 0);
						}
						if (logStatus == 1) {
							/*GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rYou has successfully logged to your account!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;*/
							((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rWrong username or password!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							enet_peer_disconnect_later(peer, 0);
						}
#else
						
						((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length()>18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
						if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that don't know how name looks!";
#endif
					}
					for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";
					
					if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
					{
						((PlayerInfo*)(event.peer->data))->country = "us";
					}
					if (isCustomFlag1(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../flags/th";
					}
					if (isCustomFlag2(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../rtsoft_logo";//rtsoft_logo
					}
					if (isVIPFlag(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../token_icon_overlay";
					}
					if (isNormalAdminFlag(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../particle/star";
					}
					if (isSuperAdminFlag(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../flags/lg";
					}
					if (isDevFlag(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../atomic_button";
					}
					/*GamePacket p3= packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
					//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
					ENetPacket * packet3 = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet3);
					enet_host_flush(server);*/

					GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), ((PlayerInfo*)(event.peer->data))->haveGrowId), ((PlayerInfo*)(peer->data))->tankIDName), ((PlayerInfo*)(peer->data))->tankIDPass));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;

					
				}
				string pStr = GetTextPointerFromPacket(event.packet);
				//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
				if(pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
				{
#ifdef TOTAL_LOG
					cout << "And we are in!" << endl;
#endif
					ENetPeer* currentPeer;
					((PlayerInfo*)(event.peer->data))->isIn = true;
					/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just entered the game..."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);

						enet_host_flush(server);
						delete p.data;
					}*/
					sendWorldOffers(peer);
					int count = 0;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						count++;
					}
					string name = ((PlayerInfo*)(peer->data))->displayName;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Server made by `bJordan `o( Jordan#0495 )"));
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Original open source code by `rGrowtopia Noobs"));
					GamePacket p4 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Welcome back, `w" + name + "`o. No friends are online."));
					GamePacket p5 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Where would you like to go? (`w" + std::to_string(count) + " `oonline)"));
					ENetPacket * packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					ENetPacket * packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					ENetPacket * packet3 = enet_packet_create(p3.data, p3.len, ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet3);
					ENetPacket * packet4 = enet_packet_create(p4.data, p4.len, ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet4);
					ENetPacket * packet5 = enet_packet_create(p5.data, p5.len, ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet5);
					//enet_host_flush(server);
					delete p.data;
					PlayerInventory inventory;
					for (int i = 0; i < 200; i++)
					{
						InventoryItem it;
						it.itemID = (i * 2) + 2;
						it.itemCount = 200;
						inventory.items.push_back(it);
					}
					((PlayerInfo*)(event.peer->data))->inventory = inventory;

					{
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wSeptember 10:`` `5Surgery Stars end!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello Growtopians,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Surgery Stars is over! We hope you enjoyed it and claimed all your well-earned Summer Tokens!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|As we announced earlier, this month we are releasing the feature update a bit later, as we're working on something really cool for the monthly update and we're convinced that the wait will be worth it!|left|\n\nadd_spacer|small|\n\nadd_textbox|Check the Forum here for more information!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wSeptember Updates Delay``|noflags|https://www.growtopiagame.com/forums/showthread.php?510657-September-Update-Delay&p=3747656|Open September Update Delay Announcement?|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're glad to invite you to take part in our official Growtopia survey!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wTake Survey!``|noflags|https://ubisoft.ca1.qualtrics.com/jfe/form/SV_1UrCEhjMO7TKXpr?GID=26674|Open the browser to take the survey?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Click on the button above and complete the survey to contribute your opinion to the game and make Growtopia even better! Thanks in advance for taking the time, we're looking forward to reading your feedback!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed PAW, we made a special video sneak peek from the latest PAW fashion show, check it out on our official YouTube channel! Yay!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wPAW 2018 Fashion Show``|noflags|https://www.youtube.com/watch?v=5i0IcqwD3MI&feature=youtu.be|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other September updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|IOTM: The Sorcerer's Tunic of Mystery|left|24|\n\nadd_label_with_icon|small|New Legendary Summer Clash Branch|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The Growtopia Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wOfficial YouTube Channel``|noflags|https://www.youtube.com/c/GrowtopiaOfficial|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_url_button|comment|`wSeptember's IOTM: `8Sorcerer's Tunic of Mystery!````|noflags|https://www.growtopiagame.com/forums/showthread.php?450065-Item-of-the-Month&p=3392991&viewfull=1#post3392991|Open the Growtopia website to see item of the month info?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopia on Facebook``|noflags|http://growtopiagame.com/facebook|Open the Growtopia Facebook page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTD: `1THELOSTGOLD`` by `#iWasToD````|NOFLAGS|OPENWORLD|THELOSTGOLD|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1Yodeling Kid - Growtopia Animation``|NOFLAGS|https://www.youtube.com/watch?v=UMoGmnFvc58|Watch 'Yodeling Kid - Growtopia Animation' by HyerS on YouTube?|0|0|\nend_dialog|gazette||OK|"));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wProject Command``|left|5016||\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`2UPDATES:`` `wFixed Crash Bug|left|112|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds (and accounts)`` might be deleted at any time if database issues appear (once per week).|left|780|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new account updates, which will cause database incompatibility.|left|780|\nadd_spacer|small|\n\nadd_url_button||``Youtube: `1Developer's Channel``|NOFLAGS|https://www.youtube.com/nitespicy|Open link?|0|0|\nadd_url_button||``Discord: `1Server Discord``|NOFLAGS|https://discord.gg/kkZtp3Q|Open link?|0|0|\nadd_url_button||``Items: `1Item database by Nenkai``|NOFLAGS|https://raw.githubusercontent.com/Nenkai/GrowtopiaItemDatabase/master/GrowtopiaItemDatabase/CoreData.txt|Open link?|0|0|\nadd_textbox|Server IP : 103.91.204.176|small|\nadd_textbox|Growtopia TH version 2.000|small|\nadd_quick_exit|\nend_dialog|gazette||OK|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
				if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
				{
					if (itemsDat != NULL) {
						ENetPacket * packet = enet_packet_create(itemsDat,
							itemsDatSize + 60,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						((PlayerInfo*)(peer->data))->isUpdating = true;
						enet_peer_disconnect_later(peer, 0);
						//enet_host_flush(server);
					}
					// TODO FIX refresh_item_data ^^^^^^^^^^^^^^
				}
				break;
			}
			default:
				cout << "Unknown packet type " << messageType << endl;
				break;
			case 3:
			{
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				std::stringstream ss(GetTextPointerFromPacket(event.packet));
				std::string to;
				bool isJoinReq = false;
				while (std::getline(ss, to, '\n')) {
					string id = to.substr(0, to.find("|"));
					string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
					if (id == "name" && isJoinReq)
					{
#ifdef TOTAL_LOG
						cout << "Entering some world..." << endl;
#endif
						try {
							WorldInfo info = worldDB.get(act);
							sendWorld(peer, &info);
							/*string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
							string worldName = "TEST";
							int xSize=100;
							int ySize=60;
							int square = xSize*ySize;
							__int16 nameLen = worldName.length();
							int payloadLen = asdf.length() / 2;
							int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8)+4;
							BYTE* data = new BYTE[dataLen];
							for (int i = 0; i < asdf.length(); i += 2)
							{
							char x = ch2n(asdf[i]);
							x = x << 4;
							x += ch2n(asdf[i + 1]);
							memcpy(data + (i / 2), &x, 1);
							}
							int zero = 0;
							__int16 item = 0;
							int smth = 0;
							for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
							for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
							memcpy(data + payloadLen, &nameLen, 2);
							memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
							memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
							memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
							memcpy(data + payloadLen + 10 + nameLen, &square, 4);
							for (int i = 0; i < 1700; i++) {
							__int16 bed = 100;
							memcpy(data + payloadLen + (i * 8) + 14 + nameLen + (8 * 100 * 37), &bed, 2);
							}
							for (int i = 0; i < 600; i++) {
							__int16 bed = 8;
							memcpy(data + payloadLen + (i*8) + 14 + nameLen + (8*100*54), &bed, 2);
							}
							memcpy(data + dataLen-4, &smth, 4);
							ENetPacket * packet2 = enet_packet_create(data,
							dataLen,
							ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							enet_host_flush(server);*/

							int x = 3040;
							int y = 736;

							for (int j = 0; j < info.width*info.height; j++)
							{
								if (info.items[j].foreground == 6) {
									x = (j%info.width) * 32;
									y = (j / info.width) * 32;
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
							//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
							delete p.data;
							((PlayerInfo*)(event.peer->data))->netID = cId;
							onPeerConnect(peer);
							cId++;

							sendInventory(peer, ((PlayerInfo*)(event.peer->data))->inventory);



							/*int resx = 95;
							int resy = 23;*/

							/*for (int i = 0; i < world.width*world.height; i++)
							{
							if (world.items[i].foreground == 6) {
							resx = i%world.width;
							resy = i / world.width;
							}
							}

							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), resx + (world.width*resy)));
							memcpy(p2.data + 8, &(((PlayerInfo*)(event.peer->data))->netID), 4);
							ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							enet_host_flush(server);*/
						}
						catch (int e) {
							if (e == 1) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You are in EXIT!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (e == 2) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters to world name!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (e == 3) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You can't go to EXIT!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Unknown error while entering world!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
					}
						if (id == "action")
						{

							if (act == "join_request")
							{
								isJoinReq = true;
							}
							if (act == "quit_to_exit")
							{
								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								sendWorldOffers(peer);

							}
							if (act == "quit")
							{
								enet_peer_disconnect_later(peer, 0);
							}
						}
					}
					break;
			}
			case 4:
			{
				{
					BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet); 
					
					if (tankUpdatePacket)
					{
						PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
						switch (pMov->packetType)
						{
						case 0:
							((PlayerInfo*)(event.peer->data))->x = pMov->x;
							((PlayerInfo*)(event.peer->data))->y = pMov->y;
							((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
							sendPData(peer, pMov);
							if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
							{
								((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
								updateAllClothes(peer);
							}
							break;

						default:
							break;
						}
						PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
						//cout << data2->packetType << endl;
						if (data2->packetType == 11)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
							//sendDrop(((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, pMov->punchX, 1, 0);
							// lets take item
						}
						if (data2->packetType == 7)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
							/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
							//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);
							enet_host_flush(server);*/
							sendWorldOffers(peer);
							// lets take item
						}
						if (data2->packetType == 10)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
							ItemDefinition def;
							try {
								def = getItemDef(pMov->plantingTree);
							}
							catch (int e) {
								goto END_CLOTHSETTER_FORCE;
							}
							
							switch (def.clothType) {
							case 0:
								if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
								break;
							case 1:
								if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth1 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
								break;
							case 2:
								if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth2 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;
								break;
							case 3:
								if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth3 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;
								break;
							case 4:
								if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth4 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;
								break;
							case 5:
								if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth5 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
								break;
							case 6:
								if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth6 = 0;
									((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
									sendState(peer);
									break;
								}
								{
									((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;
									int item = pMov->plantingTree;
									if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442) {
										((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
									}
									else {
										((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
									}
									// ^^^^ wings
									sendState(peer);
								}
								break;
							case 7:
								if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth7 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;
								break;
							case 8:
								if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth8 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;
								break;
							default:
#ifdef TOTAL_LOG
								cout << "Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
								break;
							}
							sendClothes(peer);
							// activate item
						END_CLOTHSETTER_FORCE:;
						}
						if (data2->packetType == 18)
						{
							sendPData(peer, pMov);
							// add talk buble
						}
						if (data2->punchX != -1 && data2->punchY != -1) {
							//cout << data2->packetType << endl;
							if (data2->packetType == 3)
							{
								sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
							}
							else {

							}
							/*PlayerMoving data;
							//data.packetType = 0x14;
							data.packetType = 0x3;
							//data.characterState = 0x924; // animation
							data.characterState = 0x0; // animation
							data.x = data2->punchX;
							data.y = data2->punchY;
							data.punchX = data2->punchX;
							data.punchY = data2->punchY;
							data.XSpeed = 0;
							data.YSpeed = 0;
							data.netID = ((PlayerInfo*)(event.peer->data))->netID;
							data.plantingTree = data2->plantingTree;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
							cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/
							
						}
						delete data2;
						delete pMov;
					}

					else {
						cout << "Got bad tank packet";
					}
					/*char buffer[2048];
					for (int i = 0; i < event->packet->dataLength; i++)
					{
					sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
					}
					cout << buffer;*/
				}
			}
			break;
			case 5:
				break;
			case 6:
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				break;
			}
			enet_packet_destroy(event.packet);
			break;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
			printf("Peer disconnected.\n");
#endif
			/* Reset the peer's client information. */
			/*ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left game..."));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);
				enet_host_flush(server);
			}*/
			sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
			((PlayerInfo*)(event.peer->data))->inventory.items.clear();
			delete event.peer->data;
			event.peer->data = NULL;
		}
	}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}

