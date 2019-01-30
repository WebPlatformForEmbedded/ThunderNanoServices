#pragma once

#include "../Module.h"

#include <interfaces/ITestUtility.h>

namespace WPEFramework {
namespace TestCore {

class TestCommandController
{
    private:
        using TestCommandContainer = std::map<string, Exchange::ITestUtility::ICommand*>;

        class Iterator : public Exchange::ITestUtility::ICommand::IIterator
        {
            public:
                using IteratorImpl = Core::IteratorMapType<TestCommandContainer, Exchange::ITestUtility::ICommand*, string>;

                explicit Iterator(const TestCommandContainer& commands)
                    : Exchange::ITestUtility::ICommand::IIterator()
                    , _container(commands)
                    , _iterator(_container) { }

                virtual ~Iterator() = default;

                Iterator(const Iterator&) = delete;
                Iterator& operator= (const Iterator&) = delete;

                BEGIN_INTERFACE_MAP(Iterator)
                    INTERFACE_ENTRY(Exchange::ITestUtility::ICommand::IIterator)
                END_INTERFACE_MAP

                void Reset() override {
                    _iterator.Reset(0);
                }

                bool IsValid() const override {
                    return _iterator.IsValid();
                }

                bool Next() override {
                    return _iterator.Next();
                }

                Exchange::ITestUtility::ICommand* Command() const override {
                    return *_iterator;
                }

                private:
                    TestCommandContainer _container;
                    IteratorImpl _iterator;
        };

        TestCommandController(const TestCommandController&) = delete;
        TestCommandController& operator=(const TestCommandController&) = delete;
        TestCommandController()
            : _adminLock()
            , _commands()
        {
        }

    public:
        static TestCommandController& Instance();
        ~TestCommandController() = default;

        // ITestUtility methods
        Exchange::ITestUtility::ICommand* Command(const string& name);
        Exchange::ITestUtility::ICommand::IIterator* Commands(void) const;

        // TestCommandController methods
        void Announce(Exchange::ITestUtility::ICommand* command);
        void Revoke(Exchange::ITestUtility::ICommand* command);

    private:
        mutable Core::CriticalSection _adminLock;
        TestCommandContainer _commands;
};
} // namespace TestCore
} // namespace WPEFramework
