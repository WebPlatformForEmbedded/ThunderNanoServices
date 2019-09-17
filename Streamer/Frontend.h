#pragma once

#include "Module.h"
#include "Geometry.h"
#include "PlayerPlatform.h"
#include "Administrator.h"

namespace WPEFramework {

namespace Player {

    namespace Implementation {

        class Frontend : public Exchange::IStream {
        private:
            Frontend() = delete;
            Frontend(const Frontend&) = delete;
            Frontend& operator=(const Frontend&) = delete;

            class CallbackImplementation : public Player::Implementation::ICallback {
            private:
                CallbackImplementation() = delete;
                CallbackImplementation(const CallbackImplementation&) = delete;
                CallbackImplementation& operator=(const CallbackImplementation&) = delete;

            public:
                CallbackImplementation(Frontend* parent)
                    : _parent(*parent)
                {
                }
                ~CallbackImplementation() override
                {
                }

            public:
                void TimeUpdate(uint64_t position) override
                {
                    _parent.TimeUpdate(position);
                }
                void DRM(uint32_t state) override
                {
                    _parent.DRM(state);
                }
                void StateChange(Exchange::IStream::state newState) override
                {
                    _parent.StateChange(newState);
                }

            private:
                Frontend& _parent;
            };

            class DecoderImplementation : public Exchange::IStream::IControl {
            private:
                DecoderImplementation() = delete;
                DecoderImplementation(const DecoderImplementation&) = delete;
                DecoderImplementation& operator=(const DecoderImplementation&) = delete;

            public:
                DecoderImplementation(Frontend* parent, const uint8_t decoderId)
                    : _referenceCount(1)
                    , _parent(*parent)
                    , _index(decoderId)
                    , _geometry()
                    , _player(parent->Implementation())
                    , _callback(nullptr)
                {
                }
                ~DecoderImplementation() override
                {
                    _parent.Detach();
                }

            public:
                void AddRef() const override
                {
                    Core::InterlockedIncrement(_referenceCount);
                }
                uint32_t Release() const override
                {
                    if (Core::InterlockedDecrement(_referenceCount) == 0) {
                        delete this;
                        return (Core::ERROR_DESTRUCTION_SUCCEEDED);
                    }
                    return (Core::ERROR_NONE);
                }
                uint8_t Index() const
                {
                    return (_index);
                }
                RPC::IValueIterator* Speeds() const override
                {
                    ASSERT(_player != nullptr);
                    return (Core::Service<RPC::ValueIterator>::Create<RPC::IValueIterator>(_player->Speeds()));
                }
                void Speed(const int32_t request) override
                {
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    _player->Speed(request);
                    _parent.Unlock();
                }
                int32_t Speed() const override
                {
                    uint32_t result = 0;
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    result = _player->Speed();
                    _parent.Unlock();
                    return (result);
                }
                void Position(const uint64_t absoluteTime) override
                {
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    _player->Position(absoluteTime);
                    _parent.Unlock();
                }
                uint64_t Position() const override
                {
                    uint64_t result = 0;
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    result = _player->Position();
                    _parent.Unlock();
                    return (result);
                }
                void TimeRange(uint64_t& begin, uint64_t& end) const override
                {
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    _player->TimeRange(begin, end);
                    _parent.Unlock();
                }
                IGeometry* Geometry() const override
                {
                    IGeometry* result = nullptr;
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    _geometry.Window(_player->Window());
                    _geometry.Order(_player->Order());
                    result = &_geometry;
                    _parent.Unlock();
                    return (result);
                }
                void Geometry(const IGeometry* settings) override
                {
                    _parent.Lock();
                    ASSERT(_player != nullptr);
                    Rectangle window;
                    window.X = settings->X();
                    window.Y = settings->Y();
                    window.Width = settings->Width();
                    window.Height = settings->Height();
                    _player->Window(window);
                    _player->Order(settings->Z());
                    _parent.Unlock();
                }
                void Callback(IControl::ICallback* callback) override
                {
                    _parent.Lock();
                    if (_callback != nullptr) {
                        _callback->Release();
                    }
                    if (callback != nullptr) {
                        callback->AddRef();
                    }
                    _callback = callback;
                    _parent.Unlock();
                }

                BEGIN_INTERFACE_MAP(DecoderImplementation)
                INTERFACE_ENTRY(Exchange::IStream::IControl)
                END_INTERFACE_MAP

                inline void TimeUpdate(uint64_t position)
                {
                    _parent.Lock();
                    if (_callback != nullptr) {
                        _callback->TimeUpdate(position);
                    }
                    _parent.Unlock();
                }

            private:
                mutable uint32_t _referenceCount;
                Frontend& _parent;
                uint8_t _index;
                mutable Core::Sink<Implementation::Geometry> _geometry;
                IPlayerPlatform* _player;
                IControl::ICallback* _callback;
            };

        public:
            Frontend(Administrator* administration, IPlayerPlatform* player)
                : _refCount(1)
                , _adminLock()
                , _administrator(administration)
                , _decoder(nullptr)
                , _callback(nullptr)
                , _sink(this)
                , _player(player)
            {
                ASSERT(_administrator != nullptr);
                ASSERT(_player != nullptr);

                _player->Callback(&_sink);
            }
            ~Frontend() override
            {
                ASSERT(_decoder == nullptr);
                if (_decoder != nullptr) {
                    TRACE_L1("Forcefull destruction of a stream. Forcefully removing decoder: %d", __LINE__);
                    delete _decoder;
                }
            }

        public:
            void AddRef() const override
            {
                Core::InterlockedIncrement(_refCount);
            }
            uint32_t Release() const override
            {
                uint32_t result = Core::ERROR_NONE;
                if (Core::InterlockedDecrement(_refCount) == 0) {
                    ASSERT(_player != nullptr);
                    ASSERT(_administrator != nullptr);
                    _player->Callback(nullptr);
                    _administrator->Relinquish(_player);
                    delete this;
                    result = Core::ERROR_DESTRUCTION_SUCCEEDED;
                }
                return (result);
            }
            uint8_t Index() const
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                uint8_t result = _player->Index();
                _adminLock.Unlock();
                return (result);
            }
            string Metadata() const override
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                string result = _player->Metadata();
                _adminLock.Unlock();
                return (result);
            }
            streamtype Type() const override
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                streamtype result = _player->Type();
                _adminLock.Unlock();
                return (result);
            }
            drmtype DRM() const override
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                drmtype result = _player->DRM();
                _adminLock.Unlock();
                return (result);
            }
            IControl* Control() override
            {
                _adminLock.Lock();
                if (_decoder == nullptr) {
                    ASSERT(_administrator != nullptr);
                    uint8_t decoderId =_administrator->Allocate();

                    if (decoderId != static_cast<uint8_t>(~0)) {
                        _decoder = new DecoderImplementation(this, decoderId);
                        ASSERT(_decoder != nullptr);

                        if (_decoder != nullptr) {
                            _player->AttachDecoder(decoderId);

                            // AddRef ourselves as the Control, being handed out, needs the
                            // Frontend created in this class. This is his parent class.....
                            AddRef();
                        }
                    }
                } else {
                    _decoder->AddRef();
                }
                _adminLock.Unlock();
                return (_decoder);
            }
            void Callback(IStream::ICallback* callback) override
            {
                _adminLock.Lock();
                if (_callback != nullptr) {
                    _callback->Release();
                }
                if (callback != nullptr) {
                    callback->AddRef();
                }
                _callback = callback;
                _adminLock.Unlock();
            }
            state State() const override
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                state result = _player->State();
                _adminLock.Unlock();
                return (result);
            }
            uint32_t Load(const string& configuration) override
            {
                _adminLock.Lock();
                ASSERT(_player != nullptr);
                uint32_t result = _player->Load(configuration);
                _adminLock.Unlock();
                return (result);
            }

            BEGIN_INTERFACE_MAP(Frontend)
            INTERFACE_ENTRY(Exchange::IStream)
            END_INTERFACE_MAP

        private:
            inline void TimeUpdate(uint64_t position)
            {
                _adminLock.Lock();
                if (_decoder != nullptr) {
                    _decoder->TimeUpdate(position);
                }
                _adminLock.Unlock();
            }
            void DRM(uint32_t state)
            {
                _adminLock.Lock();
                if (_callback != nullptr) {
                    _callback->DRM(state);
                }
                _adminLock.Unlock();
            }
            void StateChange(Exchange::IStream::state newState)
            {
                _adminLock.Lock();
                if (_callback != nullptr) {
                    _callback->StateChange(newState);
                }
                _adminLock.Unlock();
            }
            void Detach()
            {
                _adminLock.Lock();
                ASSERT(_decoder != nullptr);
                if (_decoder != nullptr) {
                    ASSERT(_player != nullptr);
                    ASSERT(_administrator != nullptr);
                    _player->DetachDecoder(_decoder->Index());
                    _administrator->Deallocate(_decoder->Index());
                    _decoder = nullptr;
                    Release();
                }
                _adminLock.Unlock();
            }
            IPlayerPlatform* Implementation()
            {
                return (_player);
            }
            inline void Lock() const
            {
                _adminLock.Lock();
            }
            inline void Unlock() const
            {
                _adminLock.Unlock();
            }

        private:
            mutable uint32_t _refCount;
            mutable Core::CriticalSection _adminLock;
            Administrator* _administrator;
            DecoderImplementation* _decoder;
            IStream::ICallback* _callback;
            CallbackImplementation _sink;
            IPlayerPlatform* _player;
        };

    } // Implementation

} // Player

}

