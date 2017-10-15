//#include "stdafx.h"
#include <thread>
#include <vector>
#include <memory>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>

#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Finally.h>


#include "BtChannel_Tests.h"

#include "Common.h"


using namespace osuCrypto;

namespace tests_cryptoTools
{
	void BtNetwork_AnonymousMode_Test()
	{
		IOService ioService(0);
		Session s1(ioService, "127.0.0.1", 1212, EpMode::Server);
		Session s2(ioService, "127.0.0.1", 1212, EpMode::Server);

		Session c1(ioService, "127.0.0.1", 1212, EpMode::Client);
		Session c2(ioService, "127.0.0.1", 1212, EpMode::Client);

		auto ch1 = c1.addChannel();
		auto ch2 = c2.addChannel();

		auto sch1 = s1.addChannel();
		auto sch2 = s2.addChannel();

		std::string m1 = "m1";
		std::string m2 = "m2";


		ch1.send(m1);
		ch2.send(m2);

		std::string t;
		sch1.recv(t);

		if (m1 != t)
			throw UnitTestFail();

		sch2.recv(t);

		if (m2 != t)
			throw UnitTestFail();

		if (ch1.getName() != sch1.getName())
			throw UnitTestFail();

		if (ch2.getName() != sch2.getName())
			throw UnitTestFail();

		if (s1.getName() != c1.getName())
			throw UnitTestFail();

		if (s2.getName() != c2.getName())
			throw UnitTestFail();

	}

	void BtNetwork_CancelChannel_Test()
	{
		u64 trials = 10;

		for (u64 i = 0; i < trials; ++i)
		{
			IOService ioService(0);

			{
				Session c1(ioService, "127.0.0.1", 1212, EpMode::Client);
				auto ch1 = c1.addChannel();

				ch1.cancel();

				bool throws = false;

				try { ch1.waitForConnection(); }
				catch (...) { throws = true; }

				if (throws == false)
					throw UnitTestFail();
			}

			{
				Session c1(ioService, "127.0.0.1", 1212, EpMode::Server);
				auto ch1 = c1.addChannel();

				ch1.cancel();

				bool throws = false;

				try { ch1.waitForConnection(); }
				catch (...) { throws = true; }

				if (throws == false)
					throw UnitTestFail();
			}



			{
				Session c1(ioService, "127.0.0.1", 1212, EpMode::Server);
				Session s1(ioService, "127.0.0.1", 1212, EpMode::Client);
				auto ch1 = c1.addChannel();
				auto ch0 = s1.addChannel();


				auto thrd = std::thread([&]() {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					ch1.cancel();
				});

				bool throws = false;
				std::vector<u8> rr;
				try { ch1.recv(rr); }
				catch (...) { throws = true; }

				if (throws == false)
					throw UnitTestFail();

				thrd.join();
			}


			{
				Session c1(ioService, "127.0.0.1", 1212, EpMode::Server);
				auto ch1 = c1.addChannel();


				auto thrd = std::thread([&]() {
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					ch1.cancel();
				});

				bool throws = false;
				std::vector<u8> rr(10);
				try {
					ch1.send(rr);
				}
				catch (...) { throws = true; }

				if (throws == false)
					throw UnitTestFail();
				thrd.join();
			}
		}

	}

	void BtNetwork_ServerMode_Test()
	{
		u64 numConnect = 128;
		IOService ioService(0);
		std::vector<std::array<Channel, 2>> srvChls(numConnect), clientChls(numConnect);

		for (u64 i = 0; i < numConnect; ++i)
		{
			Session s1(ioService, "127.0.0.1", 1212, EpMode::Server);
			Session c1(ioService, "127.0.0.1", 1212, EpMode::Client);
			srvChls[i][0] = s1.addChannel();
			srvChls[i][1] = s1.addChannel();
			clientChls[i][0] = c1.addChannel();
			clientChls[i][1] = c1.addChannel();

			std::string m0("c0");
			clientChls[i][0].asyncSend(std::move(m0));
			std::string m1("c1");
			clientChls[i][1].asyncSend(std::move(m1));
		}

		for (u64 i = 0; i < numConnect; ++i)
		{
			std::string m;
			srvChls[i][0].recv(m);
			if (m != "c0") throw UnitTestFail();
			srvChls[i][1].recv(m);
			if (m != "c1") throw UnitTestFail();
		}
		/////////////////////////////////////////////////////////////////////////////

		for (u64 i = 0; i < numConnect; ++i)
		{
			Session s1(ioService, "127.0.0.1", 1212, EpMode::Server);
			Session c1(ioService, "127.0.0.1", 1212, EpMode::Client);
			clientChls[i][0] = c1.addChannel();
			clientChls[i][1] = c1.addChannel();

			srvChls[i][0] = s1.addChannel();
			srvChls[i][1] = s1.addChannel();

			std::string m0("c0");
			srvChls[i][0].asyncSend(std::move(m0));
			std::string m1("c1");
			srvChls[i][1].asyncSend(std::move(m1));

		}
		//auto s = ioService.mAcceptors.size();
		//auto& a = ioService.mAcceptors.front();
		//auto thrd = std::thread([&]() {
		//	//while (stop == false)
		//	//{
		//		std::this_thread::sleep_for(std::chrono::seconds(1));
		//		for (auto& group : a.mAnonymousClientEps)
		//		{
		//			std::cout << "anClient: ";
		//			group.print();
		//		}
		//		for (auto& group : a.mAnonymousServerEps)
		//		{
		//			std::cout << "anServer: ";
		//			group.print();
		//		}
		//		for (auto& group : a.mSessionGroups)
		//		{
		//			std::cout << "Group: ";
		//			group.second.print();
		//		}
		//	//}
		//});

		for (u64 i = 0; i < numConnect; ++i)
		{
			std::string m;
			clientChls[i][0].recv(m);
			if (m != "c0") throw UnitTestFail();
			clientChls[i][1].recv(m);
			if (m != "c1") throw UnitTestFail();

		}

		//thrd.join();
	}

	void BtNetwork_Connect1_Test()
	{
		setThreadName("Test_Host");

		std::string channelName{ "TestChannel" };
		std::string msg{ "This is the message" };

		IOService ioService(0);
		auto thrd = std::thread([&]()
		{
			setThreadName("Test_Client");

			Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
			Channel chl = endpoint.addChannel(channelName, channelName);

			std::string recvMsg;
			chl.recv(recvMsg);

			if (recvMsg != msg) throw UnitTestFail();

			chl.asyncSend(std::move(recvMsg));
		});

		Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");
		auto chl = endpoint.addChannel(channelName, channelName);

		chl.asyncSend(msg);

		std::string clientRecv;
		chl.recv(clientRecv);

		if (clientRecv != msg) throw UnitTestFail();

		thrd.join();
	}


	void BtNetwork_OneMegabyteSend_Test()
	{
		setThreadName("Test_Host");

		std::string channelName{ "TestChannel" };
		std::string msg{ "This is the message" };
		std::vector<u8> oneMegabyte((u8*)msg.data(), (u8*)msg.data() + msg.size());
		oneMegabyte.resize(1000000);

		memset(oneMegabyte.data() + 100, 0xcc, 1000000 - 100);

		IOService ioService(0);

		auto thrd = std::thread([&]()
		{
			setThreadName("Test_Client");

			Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
			Channel chl = endpoint.addChannel(channelName, channelName);

			std::vector<u8> srvRecv;
			chl.recv(srvRecv);
			if (srvRecv != oneMegabyte) throw UnitTestFail();
			chl.asyncSend(std::move(srvRecv));
		});


		Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");
		auto chl = endpoint.addChannel(channelName, channelName);

		chl.asyncSend(oneMegabyte);

		std::vector<u8> clientRecv;
		chl.recv(clientRecv);

		thrd.join();

		if (clientRecv != oneMegabyte)
			throw UnitTestFail();
	}


	void BtNetwork_ConnectMany_Test()
	{
		//InitDebugPrinting();
		setThreadName("Test_Host");

		std::string channelName{ "TestChannel" };

		u64 numChannels(15);
		u64 messageCount(15);

		bool print(false);

		std::vector<u8> buff(64);

		buff.data()[14] = 3;
		buff.data()[24] = 6;
		buff.data()[34] = 8;
		buff.data()[44] = 2;

		std::thread serverThrd = std::thread([&]()
		{
			IOService ioService;
			setThreadName("Test_client");

			Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");

			std::vector<std::thread> threads;

			for (u64 i = 0; i < numChannels; i++)
			{
				threads.emplace_back([i, &buff, &endpoint, messageCount, print, channelName]()
				{
					setThreadName("Test_client_" + std::to_string(i));
					auto chl = endpoint.addChannel(channelName + std::to_string(i), channelName + std::to_string(i));
					std::vector<u8> mH;

					for (u64 j = 0; j < messageCount; j++)
					{
						chl.recv(mH);
						if (buff != mH)throw UnitTestFail();
						chl.asyncSend(std::move(mH));
					}

				});
			}


			for (auto& thread : threads)
				thread.join();
		});

		IOService ioService;

		Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

		std::vector<std::thread> threads;

		for (u64 i = 0; i < numChannels; i++)
		{
			threads.emplace_back([i, &endpoint, &buff, messageCount, print, channelName]()
			{
				setThreadName("Test_Host_" + std::to_string(i));
				auto chl = endpoint.addChannel(channelName + std::to_string(i), channelName + std::to_string(i));
				std::vector<u8> mH(buff);

				for (u64 j = 0; j < messageCount; j++)
				{
					chl.asyncSendCopy(mH);
					chl.recv(mH);

					if (buff != mH)throw UnitTestFail();
				}
			});
		}



		for (auto& thread : threads)
			thread.join();

		serverThrd.join();
	}


	void BtNetwork_CrossConnect_Test()
	{
		const block send = _mm_set_epi64x(123412156, 123546);
		const block recv = _mm_set_epi64x(7654333, 8765433);

		auto thrd = std::thread([&]() {
			IOService ioService(0);
			Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");


			auto sendChl1 = endpoint.addChannel("send", "recv");
			auto recvChl1 = endpoint.addChannel("recv", "send");

			block temp;

			sendChl1.asyncSendCopy(send);
			recvChl1.recv(temp);

			if (neq(temp, send))
				throw UnitTestFail();

			recvChl1.asyncSendCopy(recv);
			sendChl1.recv(temp);

			if (neq(temp, recv))
				throw UnitTestFail();

			recvChl1.close();
			sendChl1.close();

			endpoint.stop();

			ioService.stop();
		});
		IOService ioService(0);
		Session endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");


		auto recvChl0 = endpoint.addChannel("recv", "send");
		auto sendChl0 = endpoint.addChannel("send", "recv");

		block temp;

		sendChl0.asyncSendCopy(send);
		recvChl0.recv(temp);

		if (neq(temp, send))
			throw UnitTestFail();

		recvChl0.asyncSendCopy(recv);
		sendChl0.recv(temp);

		if (neq(temp, recv))
			throw UnitTestFail();


		thrd.join();
	}


	void BtNetwork_ManySessions_Test()
	{
		u64 nodeCount = 10;
		u32 basePort = 1212;
		std::string ip("127.0.0.1");
		//InitDebugPrinting();

		std::vector<std::thread> nodeThreads(nodeCount);

		setThreadName("main");

		for (u64 i = 0; i < nodeCount; ++i)
		{
			nodeThreads[i] = std::thread([&, i]() {

				setThreadName("node" + std::to_string(i));


				u32 port;// = basePort + i;
				IOService ioService(0);
				ioService.printErrorMessages(true);

				std::list<Session> endpoints;
				std::vector<Channel> channels;

				for (u64 j = 0; j < nodeCount; ++j)
				{
					if (j != i)
					{
						EpMode host = i > j ? EpMode::Server : EpMode::Client;
						std::string name("endpoint:");
						if (host == EpMode::Server)
						{
							name += std::to_string(i) + "->" + std::to_string(j);
							port = basePort + (u32)i;
						}
						else
						{
							name += std::to_string(j) + "->" + std::to_string(i);
							port = basePort + (u32)j;
						}

						endpoints.emplace_back(ioService, ip, port, host, name);

						channels.push_back(endpoints.back().addChannel("chl", "chl"));
					}
				}
				for (u64 j = 0, idx = 0; idx < nodeCount; ++j, ++idx)
				{
					if (j == i)
					{
						++idx;
						if (idx == nodeCount)
							break;
					}

					std::string msg = "hello" + std::to_string(idx);
					channels[j].asyncSend(std::move(msg));
				}

				std::string expected = "hello" + std::to_string(i);

				for (auto& chl : channels)
				{
					std::string msg;
					chl.recv(msg);

					if (msg != expected)
						throw UnitTestFail();
				}
				//std::cout << IoStream::lock << "re " << i << std::endl << IoStream::unlock;

				for (auto& chl : channels)
					chl.close();

				for (auto& endpoint : endpoints)
					endpoint.stop();


				ioService.stop();
			});
		}

		for (u64 i = 0; i < nodeCount; ++i)
			nodeThreads[i].join();
	}

	void BtNetwork_AsyncConnect_Test()
	{
		setThreadName("Test_Host");


		std::string channelName{ "TestChannel" };
		std::string msg{ "This is the message" };

		IOService ioService(4);

		Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
		auto chl1 = ep1.addChannel(channelName, channelName);
		Finally cleanup1([&]() { chl1.close(); ep1.stop(); ioService.stop(); });

		if (chl1.isConnected() == true) throw UnitTestFail();


		Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");
		Finally cleanup2([&]() { ep2.stop(); });

		if (chl1.isConnected() == true) throw UnitTestFail();


		auto chl2 = ep2.addChannel(channelName, channelName);
		Finally cleanup3([&]() { chl2.close(); });

		chl1.waitForConnection();

		if (chl1.isConnected() == false) throw UnitTestFail();
	}

	void BtNetwork_std_Containers_Test()
	{
		setThreadName("Test_Host");
		std::string channelName{ "TestChannel" }, msg{ "This is the message" };
		IOService ioService;

		Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
		Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

		auto chl1 = ep1.addChannel(channelName, channelName);
		auto chl2 = ep2.addChannel(channelName, channelName);

		Finally cleanup([&]() {
			chl1.close();
			chl2.close();
			ep1.stop();
			ep2.stop();
			ioService.stop();
		});


		std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
		std::array<u32, 10> arr_u32_10;
		chl1.send(vec_u32);
		chl2.recv(arr_u32_10);

		if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
			throw UnitTestFail("send vec, recv array");




		chl2.asyncSend(std::move(vec_u32));
		chl1.recv(vec_u32);

		if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
			throw UnitTestFail("send vec, recv array");



		std::string hello{ "hello world" };
		chl2.asyncSend(std::move(hello));
		chl1.recv(hello);

		if (hello != "hello world") UnitTestFail("std::string move");


	}


	void BtNetwork_bitVector_Test()
	{
		setThreadName("Test_Host");
		std::string channelName{ "TestChannel" }, msg{ "This is the message" };
		IOService ioService;

		Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
		Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

		auto chl1 = ep1.addChannel(channelName, channelName);
		auto chl2 = ep2.addChannel(channelName, channelName);


		BitVector bb(77);
		bb[55] = 1;
		bb[33] = 1;

		chl1.send(bb);
		chl2.recv(bb);


		if (!bb[55] || !bb[33])
			throw UnitTestFail();


	}



	void BtNetwork_recvErrorHandler_Test()
	{


		setThreadName("Test_Host");
		std::string channelName{ "TestChannel" }, msg{ "This is the message" };
		IOService ioService;

		ioService.printErrorMessages(false);

		Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
		Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

		auto chl1 = ep1.addChannel(channelName, channelName);
		auto chl2 = ep2.addChannel(channelName, channelName);

		Finally cleanup([&]() {
			chl1.close();
			chl2.close();
			ep1.stop();
			ep2.stop();
			ioService.stop();
		});


		std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
		std::array<u32, 3> arr_u32_3;

		chl1.send(vec_u32);

		bool throws = true;
		try
		{

			chl2.recv(arr_u32_3);
			throws = false;
		}
		catch (BadReceiveBufferSize e)
		{
			if (e.mSize != vec_u32.size() * sizeof(u32))
				throw UnitTestFail();

			std::vector<u32> backup(vec_u32.size());

			e.mRescheduler((u8*)backup.data());

			if (std::mismatch(vec_u32.begin(), vec_u32.end(), backup.begin()).first != vec_u32.end())
				throw UnitTestFail("send vec, recv backup");
		}

		if (throws == false)
			throw UnitTestFail("No throw on back recv size");


		std::array<u32, 10> arr_u32_10;
		chl1.send(vec_u32);
		chl2.recv(arr_u32_10);

		if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
			throw UnitTestFail("failed to recover bad recv size.");
	}

	void BtNetwork_closeOnError_Test()
	{

		bool throws = false;
		try {

			setThreadName("Test_Host");
			std::string channelName{ "TestChannel" }, msg{ "This is the message" };
			IOService ioService;

			ioService.printErrorMessages(false);

			Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
			Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

			auto chl1 = ep1.addChannel(channelName, channelName);

			Finally cleanup([&]() {
				chl1.close();
				ep1.stop();
				ep2.stop();
				ioService.stop();
			});


			{
				auto chl2 = ep2.addChannel(channelName, channelName);
				chl2.close();
			}

			std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
			chl1.recv(vec_u32);

		}
		catch (std::runtime_error e)
		{
			throws = true;
		}


		if (throws == false)
		{
			throw UnitTestFail("no throw");
		}

		throws = false;

		try {

			setThreadName("Test_Host");
			std::string channelName{ "TestChannel" }, msg{ "This is the message" };
			IOService ioService;
			ioService.printErrorMessages(false);

			Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
			Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

			auto chl1 = ep1.addChannel(channelName, channelName);
			auto chl2 = ep2.addChannel(channelName, channelName);

			//Finally cleanup([&]() {
			//    chl2.close();
			//    ep1.stop();
			//    ep2.stop();
			//    ioService.stop();
			//});


			std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
			chl1.send(vec_u32);
			chl1.close();


			chl2.recv(vec_u32);
			chl2.recv(vec_u32);

		}
		catch (std::runtime_error e)
		{
			throws = true;
		}


		if (throws == false)
		{
			throw UnitTestFail("no throw");
		}


	}

	void BtNetwork_SocketInterface_Test()
	{

		try {
			//auto i = new std::future<int>();
			//{
			//    std::promise<int> p;
			//}
			//{
			//    std::promise<int> p;
			//    p.set_value(1);
			//}

			//{
			//    std::promise<int> p;
			//    *i = p.get_future();
			//    //p.set_value(1);
			//}
			//i->get();
			//delete i;
			//return;

			std::string channelName{ "TestChannel" }, msg{ "This is the message" };
			IOService ioService;

			ioService.printErrorMessages(false);

			Session ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
			Session ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

			auto chl1 = ep1.addChannel(channelName, channelName);
			auto chl2 = ep2.addChannel(channelName, channelName);

			//////////////////////////////////////////////////////////////////////////
			//////////////////////////////////////////////////////////////////////////


			Channel ichl1(ioService, new SocketAdapter<Channel>(chl1));
			Channel ichl2(ioService, new SocketAdapter<Channel>(chl2));


			ichl1.asyncSendCopy(msg);

			std::string msg2;
			ichl2.recv(msg2);

			if (msg != msg2)
			{
				throw UnitTestFail(LOCATION);
			}
		}
		catch (std::exception e)
		{
			std::cout << "sss" << e.what() << std::endl;
		}
	}
}