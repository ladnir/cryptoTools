#pragma once

#include <sstream>
#include <array>
#include <queue>
#include <mutex>
#include <memory>
#include "cryptoTools/Network/SocketAdapter.h"
void networkTutorial();

namespace osuCrypto
{

    class LocalSocket : public SocketInterface {
    public:
        LocalSocket() = delete;
        LocalSocket(const LocalSocket&) = delete;
        LocalSocket(LocalSocket&&) = delete;

        // The shared state that the two sockets will communicate over.
        struct State {
            // The amount of data each party has buffered waiting for
            // them to read.
            std::array<u64, 2> mBufferedSize;

            // The amount of data that each party is currently requesting.
            // Once enough data has been buffered, we write this many bytes
            // to the receiver.
            std::array<u64, 2> mRequestSize;

            // The actual buffer that we will store the bytes in.
            std::array<std::stringstream, 2> mRecvBuffers;

            // The locations that each party wants their recv bytes written to.
            // The total size of these buffers will equal mRequestSize.
            std::array<std::vector<boost::asio::mutable_buffer>, 2> mRecvRequest;

            // The callback that should be called when a recv operation completes.
            std::array<io_completion_handle,2> mRecvRequestCB;

            // A mutex to make sure things are thread safe.
            std::mutex mMtx;
        };

        // Construct the LocalSocket with the provided state.
        LocalSocket(std::shared_ptr<State>& state, u64 idx) 
            : mState(state)
            , mIdx(idx) 
        {
            assert(mState && idx < 2);
        }

        std::shared_ptr<State> mState;
        u64 mIdx;
    
        // A helper function to construct a pair of sockets.
        static std::array<LocalSocket*, 2> makePair()
        {
            std::array<LocalSocket*, 2> ret;
            auto state = std::make_shared<State>();
            ret[0] = new LocalSocket(state, 0);
            ret[1] = new LocalSocket(state, 1);
            return ret;
        }

        // This fuction check to see if we have enough
        // buffered data to complete a recv operation.
        // If so then it performs the recv and callback.
        void tryRecv(u64 idx)
        {
            if (mState->mRequestSize[idx] > 0 &&
                mState->mRequestSize[idx] <= mState->mBufferedSize[idx])
            {
                for (auto& b : mState->mRecvRequest[idx])
                {
                    auto data = boost::asio::buffer_cast<char*>(b);
                    auto size = boost::asio::buffer_size(b);
                    mState->mRecvBuffers[idx].read(data, size);
                }
                mState->mRecvRequest[idx].clear();

                auto sizeRequested = mState->mRequestSize[idx];
                mState->mRequestSize[idx] = 0;
                mState->mBufferedSize[idx] -= sizeRequested;

                // Its safest to unlock before making a callback into 
                // unknown code...
                mState->mMtx.unlock();

                auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
                mState->mRecvRequestCB[idx](ec, sizeRequested);
                mState->mRecvRequestCB[idx] = {};
            }
            else
            {
                mState->mMtx.unlock();
            }

        }

        // This party has requested some data. Write the data
        // if we currently have it. Otherwise we will store the
        // request and fulfill is when the data arrives.
        void async_recv(
            span<boost::asio::mutable_buffer> buffers,
            io_completion_handle&& fn) override 
        {
            u64 sizeRequested = 0;
            for (auto& b : buffers)
                sizeRequested += b.size();

            // tryRecv will unlock.
            mState->mMtx.lock();

            // assert that we dont currently have an active
            // recv request. Only one should happen at a time.
            assert(mState->mRecvRequest[mIdx].size() == 0);

            mState->mRequestSize[mIdx] = sizeRequested;
            mState->mRecvRequest[mIdx].insert(
                mState->mRecvRequest[mIdx].end(),
                buffers.begin(), buffers.end());

            mState->mRecvRequestCB[mIdx] = std::forward<io_completion_handle>(fn);

            // will unlock.
            tryRecv(mIdx);
        }

        // This party has requested us to send some data.
        // We will write this data to the buffer and then
        // check to see if the other party has an outstanding
        // recv request. If so we will try and fulfill it.
        // Finally we call our own callback saying that the
        // data has been sent.
        void async_send(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) override 
        {
            // tryRecv will unlock.
            mState->mMtx.lock();

            u64 sendSize = 0;
            auto idx = mIdx ^ 1;
            for (auto b : buffers)
            {
                auto data = boost::asio::buffer_cast<char*>(b);
                auto size = boost::asio::buffer_size(b);
                mState->mRecvBuffers[idx].write(data, size);
                sendSize += size;
            }

            mState->mBufferedSize[idx] += sendSize;

            // will unlock.
            tryRecv(idx);

            auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
            fn(ec, sendSize);
        }

    };

}