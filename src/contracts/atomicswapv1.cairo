//  - Deploy to Starknet/Mainnet
// File: src/atomic_swap.cairo

#[starknet::contract]
mod AtomicSwapHTLC {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use core::pedersen::pedersen;
    use starknet::storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess};
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {
        swaps: Map<felt252, SwapData>,
        user_swaps: Map<(ContractAddress, u256), felt252>,
        user_swap_count: Map<ContractAddress, u256>,
        total_swaps: u256,
        supported_tokens: Map<ContractAddress, bool>,
        owner: ContractAddress,
    }

    #[derive(Drop, Serde, starknet::Store, Clone)]
    struct SwapData {
        swap_id: felt252,
        initiator: ContractAddress,
        participant: ContractAddress,
        token: ContractAddress,
        amount: u256,
        hash_lock: felt252,
        secret: felt252,
        time_lock: u64,
        zec_address: felt252,
        zec_tx_hash: felt252,
        state: SwapState,
        created_at: u64,
    }

    #[derive(Drop, Serde, starknet::Store, Clone, PartialEq)]
    enum SwapState {
        Active,
        Completed,
        Refunded,
        Expired,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SwapInitiated: SwapInitiated,
        SwapCompleted: SwapCompleted,
        SwapRefunded: SwapRefunded,
        TokenAdded: TokenAdded,
    }

    #[derive(Drop, starknet::Event)]
    struct SwapInitiated {
        #[key]
        swap_id: felt252,
        #[key]
        initiator: ContractAddress,
        participant: ContractAddress,
        token: ContractAddress,
        amount: u256,
        hash_lock: felt252,
        time_lock: u64,
        zec_address: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SwapCompleted {
        #[key]
        swap_id: felt252,
        secret: felt252,
        completed_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SwapRefunded {
        #[key]
        swap_id: felt252,
        refunded_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TokenAdded {
        token: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.total_swaps.write(0);
    }

    #[abi(embed_v0)]
    impl AtomicSwapHTLCImpl of super::IAtomicSwapHTLC<ContractState> {
        fn initiate_swap(
            ref self: ContractState,
            participant: ContractAddress,
            token: ContractAddress,
            amount: u256,
            hash_lock: felt252,
            time_lock_hours: u64,
            zec_address: felt252,
        ) -> felt252 {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let time_lock = current_time + (time_lock_hours * 3600);
            
            assert(self.supported_tokens.read(token), 'Token not supported');
            assert(time_lock > current_time, 'Invalid time lock');
            assert(amount > 0, 'Amount must be positive');
            assert(participant != caller, 'Cannot swap with self');

            // Transfer tokens to contract
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer_from(caller, starknet::get_contract_address(), amount);
            assert(success, 'Token transfer failed');

            // Generate unique swap ID
            let swap_count = self.total_swaps.read();
            let swap_id = pedersen(pedersen(caller.into(), participant.into()), swap_count.try_into().unwrap());

            // Create swap
            let swap = SwapData {
                swap_id: swap_id,
                initiator: caller,
                participant: participant,
                token: token,
                amount: amount,
                hash_lock: hash_lock,
                secret: 0,
                time_lock: time_lock,
                zec_address: zec_address,
                zec_tx_hash: 0,
                state: SwapState::Active,
                created_at: current_time,
            };

            self.swaps.write(swap_id, swap);
            
            // Track user swaps
            let user_count = self.user_swap_count.read(caller);
            self.user_swaps.write((caller, user_count), swap_id);
            self.user_swap_count.write(caller, user_count + 1);

            self.total_swaps.write(swap_count + 1);

            self.emit(SwapInitiated {
                swap_id: swap_id,
                initiator: caller,
                participant: participant,
                token: token,
                amount: amount,
                hash_lock: hash_lock,
                time_lock: time_lock,
                zec_address: zec_address,
            });

            swap_id
        }

        fn complete_swap(ref self: ContractState, swap_id: felt252, secret: felt252, zec_tx_hash: felt252) {
            let mut swap = self.swaps.read(swap_id);
            let caller = get_caller_address();
            let current_time = get_block_timestamp();

            assert(swap.state == SwapState::Active, 'Swap not active');
            assert(current_time < swap.time_lock, 'Swap expired');
            assert(caller == swap.participant, 'Only participant');

            // Verify secret matches hash lock
            let computed_hash = pedersen(secret, 0);
            assert(computed_hash == swap.hash_lock, 'Invalid secret');

            swap.state = SwapState::Completed;
            swap.secret = secret;
            swap.zec_tx_hash = zec_tx_hash;
            self.swaps.write(swap_id, swap.clone());

            // Transfer tokens to participant
            let token_dispatcher = IERC20Dispatcher { contract_address: swap.token };
            let success = token_dispatcher.transfer(swap.participant, swap.amount);
            assert(success, 'Transfer failed');

            self.emit(SwapCompleted {
                swap_id: swap_id,
                secret: secret,
                completed_at: current_time,
            });
        }

        fn refund_swap(ref self: ContractState, swap_id: felt252) {
            let mut swap = self.swaps.read(swap_id);
            let caller = get_caller_address();
            let current_time = get_block_timestamp();

            assert(swap.state == SwapState::Active, 'Swap not active');
            assert(caller == swap.initiator, 'Only initiator');
            assert(current_time >= swap.time_lock, 'Time lock not expired');

            swap.state = SwapState::Refunded;
            self.swaps.write(swap_id, swap.clone());

            // Refund tokens to initiator
            let token_dispatcher = IERC20Dispatcher { contract_address: swap.token };
            let success = token_dispatcher.transfer(swap.initiator, swap.amount);
            assert(success, 'Refund failed');

            self.emit(SwapRefunded {
                swap_id: swap_id,
                refunded_at: current_time,
            });
        }

        fn add_supported_token(ref self: ContractState, token: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            self.supported_tokens.write(token, true);
            self.emit(TokenAdded { token: token });
        }

        fn get_swap(self: @ContractState, swap_id: felt252) -> SwapData {
            self.swaps.read(swap_id)
        }

        fn get_user_swaps(self: @ContractState, user: ContractAddress) -> Array<felt252> {
            let count = self.user_swap_count.read(user);
            let mut swaps = ArrayTrait::new();
            let mut i: u256 = 0;
            loop {
                if i >= count {
                    break;
                }
                swaps.append(self.user_swaps.read((user, i)));
                i += 1;
            };
            swaps
        }

        fn is_token_supported(self: @ContractState, token: ContractAddress) -> bool {
            self.supported_tokens.read(token)
        }
    }
}

#[starknet::interface]
trait IAtomicSwapHTLC<TContractState> {
    fn initiate_swap(
        ref self: TContractState,
        participant: ContractAddress,
        token: ContractAddress,
        amount: u256,
        hash_lock: felt252,
        time_lock_hours: u64,
        zec_address: felt252,
    ) -> felt252;
    
    fn complete_swap(ref self: TContractState, swap_id: felt252, secret: felt252, zec_tx_hash: felt252);
    fn refund_swap(ref self: TContractState, swap_id: felt252);
    fn add_supported_token(ref self: TContractState, token: ContractAddress);
    fn get_swap(self: @TContractState, swap_id: felt252) -> AtomicSwapHTLC::SwapData;
    fn get_user_swaps(self: @TContractState, user: ContractAddress) -> Array<felt252>;
    fn is_token_supported(self: @TContractState, token: ContractAddress) -> bool;
}
