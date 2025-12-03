import React, { createContext, useContext, useState, useEffect } from 'react';
import { Home, Gamepad2, Wallet as WalletIcon, User, Trophy, ChevronLeft, Eye, EyeOff, Shield, Copy, AlertCircle, CheckCircle, XCircle, ArrowDownLeft, ArrowUpRight, Zap, LogOut, Timer, Brain, Coins, Users, Lock, Loader2, RefreshCw, Send, Crown, MessageSquare, Search, Calendar, LifeBuoy, ChevronUp, ChevronDown, Edit3, TrendingUp, TrendingDown, Minus, Sword, MapPin, Clock as ClockIcon } from 'lucide-react';

// ==================== CONFIGURATION ====================
const API_URL = 'http://localhost:3001/api';
const WS_URL = 'ws://localhost:3001';

// ==================== HERO AVATARS ====================
export const HEROES = [
  { id: 'hero_1', name: 'Shadow', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=shadow' },
  { id: 'hero_2', name: 'Phantom', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=phantom' },
  { id: 'hero_3', name: 'Ghost', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ghost' },
  { id: 'hero_4', name: 'Ninja', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ninja' },
  { id: 'hero_5', name: 'Raven', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=raven' },
  { id: 'hero_6', name: 'Viper', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=viper' },
  { id: 'hero_7', name: 'Specter', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=specter' },
  { id: 'hero_8', name: 'Wraith', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=wraith' },
  { id: 'hero_9', name: 'Eclipse', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=eclipse' },
  { id: 'hero_10', name: 'Void', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=void' },
  { id: 'hero_11', name: 'Cipher', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=cipher' },
  { id: 'hero_12', name: 'Matrix', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=matrix' },
  { id: 'hero_13', name: 'Quantum', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=quantum' },
  { id: 'hero_14', name: 'Nexus', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=nexus' },
  { id: 'hero_15', name: 'Pulse', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=pulse' },
  { id: 'hero_16', name: 'Vertex', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=vertex' },
  { id: 'hero_17', name: 'Zenith', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=zenith' },
  { id: 'hero_18', name: 'Apex', url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=apex' },
];

export const getHeroImage = (id: string) => HEROES.find(h => h.id === id)?.url || HEROES[0].url;

// ==================== TYPES ====================
interface User {
  playerId: string;
  username: string | null;
  email: string | null;
  avatarId: string;
  balance: number;
  isVerified: boolean;
  hideBalance: boolean;
  wins: number;
  losses: number;
  xp: number;
  level?: number;
  totalGames: number;
  streak: number;
  createdAt?: string;
  lastLogin?: string;
}

interface Transaction {
  id: string;
  type: string;
  amount: number;
  txId: string;
  status: string;
  createdAt: string;
}

interface Room {
  id: string;
  hostId: string;
  hostName: string;
  hostAvatar: string;
  type: 'PICTURE_RUSH' | 'PICTURE_MATCH';
  stake: number;
  maxPlayers: number;
  currentPlayers: number;
  status: string;
  playerIds: string[];
  playerData: any;
}

interface ChatMessage {
  id: string;
  sender: string;
  text: string;
  isCorrect: boolean;
  timestamp: number;
}

export enum GameType {
  PICTURE_RUSH = 'PICTURE_RUSH',
  PICTURE_MATCH = 'PICTURE_MATCH'
}

interface Game {
  gameId: string;
  type: GameType;
  stake: number;
  maxPlayers: number;
  currentPlayers?: number;
  status: string;
  players?: any[];
}

// ==================== API CLIENT ====================
const api = {
  async request(endpoint: string, options: any = {}) {
    const token = localStorage.getItem('zec_token');
    const headers: any = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.userMessage || data.message || 'Request failed');
    return data;
  },

  auth: {
    signup: (password: string, email?: string, username?: string) => 
      api.request('/auth/signup', { method: 'POST', body: { password, email, username } }),
    login: (playerId: string, password: string) => 
      api.request('/auth/login', { method: 'POST', body: { playerId, password } }),
    verifyToken: (token: string) => 
      api.request('/auth/verify-token', { method: 'POST', body: { token } }),
    logout: () => 
      api.request('/auth/logout', { method: 'POST', body: {} }),
  },

  account: {
    me: () => api.request('/account/me'),
    verify: (txId: string) => 
      api.request('/account/verify', { method: 'POST', body: { txId } }),
    updateUsername: (username: string) => 
      api.request('/account/username', { method: 'POST', body: { username } }),
    updateAvatar: (avatarId: string) => 
      api.request('/account/avatar', { method: 'POST', body: { avatarId } }),
    toggleBalance: () => 
      api.request('/account/toggle-balance', { method: 'POST' }),
  },

  wallet: {
    balance: () => api.request('/wallet/balance'),
    address: () => api.request('/wallet/address'),
    deposit: (txId: string) => 
      api.request('/wallet/deposit', { method: 'POST', body: { txId } }),
    withdraw: (amount: number, address: string) => 
      api.request('/wallet/withdraw', { method: 'POST', body: { amount, address } }),
    transactions: (limit?: number, offset?: number, type?: string) => {
      const params = new URLSearchParams();
      if (limit) params.append('limit', limit.toString());
      if (offset) params.append('offset', offset.toString());
      if (type) params.append('type', type);
      return api.request(`/wallet/transactions?${params}`);
    },
  },

  rooms: {
    list: (type?: string) => api.request(`/rooms${type ? `?type=${type}` : ''}`),
    get: (roomId: string) => api.request(`/rooms/${roomId}`),
    create: (type: string, stake: number, maxPlayers: number) => 
      api.request('/rooms/create', { method: 'POST', body: { type, stake, maxPlayers } }),
    join: (roomId: string) => 
      api.request('/rooms/join', { method: 'POST', body: { roomId } }),
    leave: (roomId: string) => 
      api.request(`/rooms/${roomId}/leave`, { method: 'POST' }),
  },

  game: {
    action: (gameId: string, action: string, data: any) => 
      api.request('/game/action', { method: 'POST', body: { gameId, action, data } }),
    state: (gameId: string) => api.request(`/game/${gameId}/state`),
    start: (roomId: string) => 
      api.request('/game/start', { method: 'POST', body: { roomId } }),
    history: (limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (limit) params.append('limit', limit.toString());
      if (offset) params.append('offset', offset.toString());
      return api.request(`/game/history?${params}`);
    },
  },

  leaderboard: () => api.request('/leaderboard'),
  stats: () => api.request('/stats'),
};

// ==================== STORE CONTEXT ====================
interface StoreContextType {
  user: User | null;
  isAuthenticated: boolean;
  transactions: Transaction[];
  rooms: Room[];
  activeGame: Game | null;
  currentPage: string;
  loading: boolean;
  
  signup: (password: string, email?: string, username?: string) => Promise<boolean>;
  login: (playerId: string, password: string) => Promise<boolean>;
  logout: () => void;
  verifyAccount: (txId: string) => Promise<boolean>;
  updateUsername: (username: string) => Promise<boolean>;
  updateAvatar: (avatarId: string) => Promise<void>;
  toggleHideBalance: () => Promise<void>;
  deposit: (txId: string) => Promise<boolean>;
  withdraw: (amount: number, address: string) => Promise<boolean>;
  createGame: (type: GameType, stake: number, maxPlayers: number, verified?: boolean) => Promise<void>;
  joinGame: (roomId: string) => Promise<void>;
  endGame: (won: boolean, pot: number) => void;
  fetchRooms: () => Promise<void>;
  navigate: (page: string, data?: any) => void;
  refreshUser: () => Promise<void>;
}

const StoreContext = createContext<StoreContextType | null>(null);

export const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) throw new Error('useStore must be used within StoreProvider');
  return context;
};

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [rooms, setRooms] = useState<Room[]>([]);
  const [activeGame, setActiveGame] = useState<Game | null>(null);
  const [currentPage, setCurrentPage] = useState('landing');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('zec_token');
    if (token) {
      api.auth.verifyToken(token)
        .then(() => refreshUser())
        .catch(() => {
          localStorage.removeItem('zec_token');
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []);

  const refreshUser = async () => {
    try {
      const [userData, txData] = await Promise.all([
        api.account.me(),
        api.wallet.transactions(50, 0),
      ]);
      
      setUser(userData.user);
      setIsAuthenticated(true);
      setTransactions(txData.transactions || []);
      setLoading(false);
      if (currentPage === 'landing' || currentPage === 'auth') {
        setCurrentPage('home');
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      localStorage.removeItem('zec_token');
      setIsAuthenticated(false);
      setLoading(false);
      setCurrentPage('landing');
    }
  };

  const signup = async (password: string, email?: string, username?: string) => {
    try {
      const data = await api.auth.signup(password, email, username);
      localStorage.setItem('zec_token', data.token);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Signup failed:', error);
      return false;
    }
  };

  const login = async (playerId: string, password: string) => {
    try {
      const data = await api.auth.login(playerId, password);
      localStorage.setItem('zec_token', data.token);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('zec_token');
    setUser(null);
    setIsAuthenticated(false);
    setCurrentPage('landing');
  };

  const verifyAccount = async (txId: string) => {
    try {
      await api.account.verify(txId);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Verification failed:', error);
      return false;
    }
  };

  const updateUsername = async (username: string) => {
    try {
      await api.account.updateUsername(username);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Update username failed:', error);
      return false;
    }
  };

  const updateAvatar = async (avatarId: string) => {
    try {
      await api.account.updateAvatar(avatarId);
      await refreshUser();
    } catch (error) {
      console.error('Update avatar failed:', error);
    }
  };

  const toggleHideBalance = async () => {
    try {
      await api.account.toggleBalance();
      await refreshUser();
    } catch (error) {
      console.error('Toggle balance failed:', error);
    }
  };

  const deposit = async (txId: string) => {
    try {
      await api.wallet.deposit(txId);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Deposit failed:', error);
      return false;
    }
  };

  const withdraw = async (amount: number, address: string) => {
    try {
      await api.wallet.withdraw(amount, address);
      await refreshUser();
      return true;
    } catch (error) {
      console.error('Withdraw failed:', error);
      return false;
    }
  };

  const createGame = async (type: GameType, stake: number, maxPlayers: number, verified: boolean = false) => {
    try {
      const data = await api.rooms.create(type, stake, maxPlayers);
      setActiveGame({
        gameId: data.roomId,
        type,
        stake,
        maxPlayers,
        status: 'WAITING'
      });
      setCurrentPage('room');
    } catch (error) {
      console.error('Create game failed:', error);
    }
  };

  const joinGame = async (roomId: string) => {
    try {
      await api.rooms.join(roomId);
      const roomData = await api.rooms.get(roomId);
      setActiveGame({
        gameId: roomData.room.id,
        type: roomData.room.type,
        stake: roomData.room.stake,
        maxPlayers: roomData.room.maxPlayers,
        status: roomData.room.status
      });
      setCurrentPage('room');
    } catch (error) {
      console.error('Join game failed:', error);
    }
  };

  const endGame = (won: boolean, pot: number) => {
    setActiveGame(null);
    refreshUser();
    setTimeout(() => setCurrentPage('games'), 3000);
  };

  const fetchRooms = async () => {
    try {
      const data = await api.rooms.list();
      setRooms(data.rooms || []);
    } catch (error) {
      console.error('Fetch rooms failed:', error);
    }
  };

  const navigate = (page: string, data?: any) => {
    setCurrentPage(page);
    if (data?.game) setActiveGame(data.game);
  };

  return (
    <StoreContext.Provider
      value={{
        user,
        isAuthenticated,
        transactions,
        rooms,
        activeGame,
        currentPage,
        loading,
        signup,
        login,
        logout,
        verifyAccount,
        updateUsername,
        updateAvatar,
        toggleHideBalance,
        deposit,
        withdraw,
        createGame,
        joinGame,
        endGame,
        fetchRooms,
        navigate,
        refreshUser,
      }}
    >
      {children}
    </StoreContext.Provider>
  );
};

// ==================== LANDING PAGE ====================
const Landing = () => {
  const { navigate, isAuthenticated } = useStore();

  useEffect(() => {
    if (isAuthenticated) navigate('home');
  }, [isAuthenticated]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden bg-[#050505]">
      <div className="absolute top-[-20%] left-[-20%] w-[80%] h-[80%] bg-yellow-500 opacity-[0.04] blur-[150px] rounded-full pointer-events-none animate-pulse"></div>
      <div className="absolute bottom-[-20%] right-[-20%] w-[80%] h-[80%] bg-purple-900 opacity-[0.06] blur-[150px] rounded-full pointer-events-none"></div>

      <div className="relative z-10 text-center w-full max-w-sm flex flex-col h-[80vh] justify-between py-12">
        <div className="flex-1 flex flex-col items-center justify-center">
          <div className="relative mb-8 group">
            <div className="absolute inset-0 bg-yellow-500 blur-2xl opacity-20 group-hover:opacity-40 transition-opacity duration-500"></div>
            <div className="relative inline-flex items-center justify-center w-24 h-24 rounded-3xl bg-gradient-to-br from-gray-900 to-black border border-white/10 shadow-2xl">
              <Zap size={48} className="text-yellow-500 fill-yellow-500" />
            </div>
          </div>

          <h1 className="text-7xl font-black tracking-tighter text-white mb-4 leading-[0.85]">
            ZEC<br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-b from-yellow-500 to-yellow-600">ARENA</span>
          </h1>

          <div className="flex items-center gap-3 text-xs font-bold tracking-[0.2em] text-gray-500 border border-white/5 px-4 py-2 rounded-full bg-white/5 backdrop-blur-sm">
            <Shield size={12} />
            <span>PRIVACY FIRST PVP</span>
          </div>
        </div>

        <div className="space-y-6 w-full">
          <button
            onClick={() => navigate('auth')}
            className="w-full py-6 rounded-2xl bg-white text-black font-black text-xl tracking-wider hover:scale-[1.02] active:scale-[0.98] transition-all shadow-[0_0_50px_rgba(255,255,255,0.15)] relative overflow-hidden group"
          >
            <span className="relative z-10">PLAY ANONYMOUSLY</span>
            <div className="absolute inset-0 bg-yellow-500 transform scale-x-0 group-hover:scale-x-100 transition-transform origin-left duration-300"></div>
          </button>

          <p className="text-[10px] text-gray-600 font-mono">
            POWERED BY ZCASH &bull; NO EMAIL REQUIRED
          </p>
        </div>
      </div>
    </div>
  );
};

// ==================== AUTH PAGE ====================
const Auth = () => {
  const [isLogin, setIsLogin] = useState(false);
  const [playerId, setPlayerId] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { signup, login, navigate } = useStore();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        const success = await login(playerId, password);
        if (!success) setError('Invalid ID/Username or Password');
      } else {
        if (password.length < 6) {
          setError('Password must be at least 6 characters');
          setLoading(false);
          return;
        }
        const success = await signup(password);
        if (!success) setError('Signup failed');
      }
    } catch (e) {
      setError('Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative bg-[#050505]">
      <button 
        onClick={() => navigate('landing')} 
        className="absolute top-8 left-6 text-gray-500 hover:text-white transition-colors"
      >
        <ChevronLeft size={24} />
      </button>

      <div className="w-full max-w-sm">
        <div className="text-center mb-10">
          <h1 className="text-3xl font-black tracking-tighter text-white">
            {isLogin ? 'WELCOME BACK' : 'CREATE IDENTITY'}
          </h1>
          <p className="text-gray-500 mt-2 text-xs uppercase tracking-widest">
            {isLogin ? 'Enter The Arena' : 'Secure & Anonymous'}
          </p>
        </div>

        <div className="bg-gray-800 p-8 rounded-3xl shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-yellow-500 to-transparent opacity-50"></div>

          <div className="flex gap-4 mb-8">
            <button 
              onClick={() => { setIsLogin(false); setError(''); }}
              className={`flex-1 pb-2 text-sm font-bold tracking-wide transition-colors border-b-2 ${!isLogin ? 'border-yellow-500 text-white' : 'border-transparent text-gray-600 hover:text-gray-400'}`}
            >
              SIGN UP
            </button>
            <button 
              onClick={() => { setIsLogin(true); setError(''); }}
              className={`flex-1 pb-2 text-sm font-bold tracking-wide transition-colors border-b-2 ${isLogin ? 'border-yellow-500 text-white' : 'border-transparent text-gray-600 hover:text-gray-400'}`}
            >
              LOGIN
            </button>
          </div>

          <div className="space-y-5">
            {isLogin && (
              <div className="relative group">
                <Shield className="absolute left-4 top-3.5 text-gray-500 group-focus-within:text-yellow-500 transition-colors" size={18} />
                <input 
                  type="text" 
                  placeholder="Player ID or Username"
                  value={playerId}
                  onChange={(e) => setPlayerId(e.target.value)}
                  className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 transition-all"
                />
              </div>
            )}

            <div className="relative group">
              <Lock className="absolute left-4 top-3.5 text-gray-500 group-focus-within:text-yellow-500 transition-colors" size={18} />
              <input 
                type={showPwd ? "text" : "password"} 
                placeholder={isLogin ? "Password" : "Create Password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 transition-all"
              />
              <button 
                type="button"
                onClick={() => setShowPwd(!showPwd)}
                className="absolute right-4 top-3.5 text-gray-500 hover:text-white transition-colors"
              >
                {showPwd ? <EyeOff size={18}/> : <Eye size={18}/>}
              </button>
            </div>

            {error && <div className="text-red-400 text-xs text-center font-medium bg-red-900/20 py-2 rounded-lg border border-red-500/20">{error}</div>}

            <button 
              onClick={handleSubmit}
              disabled={loading}
              className="w-full bg-yellow-500 text-black font-bold py-4 rounded-xl mt-2 hover:bg-yellow-400 hover:scale-[1.02] active:scale-[0.98] transition-all shadow-[0_0_20px_rgba(244,183,40,0.3)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Processing...' : isLogin ? 'ENTER ARENA' : 'CREATE ID & PLAY'}
            </button>
          </div>

          {!isLogin && (
            <p className="text-[10px] text-gray-500 text-center mt-6 leading-relaxed">
              By creating an ID, you agree that lost passwords can only be recovered via support.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

// ==================== HOME PAGE ====================
const Home = () => {
  const { user, navigate } = useStore();

  return (
    <div className="p-6 pt-8 pb-24">
      <header className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-gray-400 text-xs uppercase tracking-widest font-semibold">Welcome back</h2>
          <h1 className="text-2xl font-bold text-white">
            {user?.username || `Agent ${user?.playerId.slice(0, 6)}`}
          </h1>
        </div>
        <button onClick={() => navigate('profile')} className="w-12 h-12 rounded-full bg-gradient-to-br from-yellow-500 to-orange-600 p-[2px]">
          <div className="w-full h-full rounded-full bg-black overflow-hidden">
            <img src={getHeroImage(user?.avatarId || 'hero_1')} alt="Profile" className="w-full h-full object-cover" />
          </div>
        </button>
      </header>

      <div className="space-y-6">
        <div className="bg-gradient-to-br from-yellow-900/40 to-black p-6 rounded-3xl border border-yellow-500/20 relative overflow-hidden group">
          <div className="absolute -right-10 -top-10 w-40 h-40 bg-yellow-500/10 rounded-full blur-3xl group-hover:bg-yellow-500/20 transition-all"></div>
          <div className="relative z-10">
            <h3 className="text-3xl font-black italic text-white mb-1">PVP MODE</h3>
            <p className="text-yellow-500 font-medium mb-4">Stake ZEC. Win Big.</p>
            <button onClick={() => navigate('games')} className="inline-flex items-center gap-2 bg-white text-black px-5 py-2.5 rounded-full font-bold text-sm hover:bg-yellow-500 transition-colors">
              Play Now <ArrowRight size={16} />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-800 p-4 rounded-2xl border border-white/5 hover:border-yellow-500/30 transition-colors">
            <Zap className="text-yellow-500 mb-3" size={24} />
            <h4 className="font-bold text-sm mb-1">Fast Payouts</h4>
            <p className="text-[10px] text-gray-400">90% of the pot goes to the winner instantly.</p>
          </div>
          <div className="bg-gray-800 p-4 rounded-2xl border border-white/5 hover:border-yellow-500/30 transition-colors">
            <Shield className="text-yellow-500 mb-3" size={24} />
            <h4 className="font-bold text-sm mb-1">Privacy First</h4>
            <p className="text-[10px] text-gray-400">No email needed. Justimport React, { createContext, useContext, useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { Home, Gamepad2, Wallet, User, Trophy, Calendar } from 'lucide-react';

// ==================== TYPES ====================
interface User {
  playerId: string;
  username: string | null;
  email: string | null;
  avatarId: string;
  balance: number;
  isVerified: boolean;
  hideBalance: boolean;
  wins: number;
  losses: number;
  xp: number;
  level?: number;
  totalGames: number;
  streak: number;
}

interface Transaction {
  id: string;
  type: string;
  amount: number;
  txId: string;
  status: string;
  createdAt: string;
}

interface Room {
  id: string;
  hostId: string;
  hostName: string;
  hostAvatar: string;
  type: 'PICTURE_RUSH' | 'PICTURE_MATCH';
  stake: number;
  maxPlayers: number;
  currentPlayers: number;
  status: string;
  playerIds: string[];
}

interface Game {
  gameId: string;
  type: 'PICTURE_RUSH' | 'PICTURE_MATCH';
  stake: number;
  players: any[];
  status: string;
}

// ==================== API CONFIG ====================
const API_URL = 'http://localhost:3001/api';

const api = {
  async request(endpoint: string, options: any = {}) {
    const token = localStorage.getItem('token');
    const headers: any = {
      'Content-Type': 'application/json',
      ...options.headers,
    };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Request failed');
    return data;
  },

  auth: {
    signup: (password: string, email?: string, username?: string) =>
      api.request('/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ password, email, username }),
      }),
    login: (playerId: string, password: string) =>
      api.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ playerId, password }),
      }),
    verifyToken: (token: string) =>
      api.request('/auth/verify-token', {
        method: 'POST',
        body: JSON.stringify({ token }),
      }),
  },

  account: {
    getMe: () => api.request('/account/me'),
    verify: (txId: string) =>
      api.request('/account/verify', {
        method: 'POST',
        body: JSON.stringify({ txId }),
      }),
    updateUsername: (username: string) =>
      api.request('/account/username', {
        method: 'POST',
        body: JSON.stringify({ username }),
      }),
    updateAvatar: (avatarId: string) =>
      api.request('/account/avatar', {
        method: 'POST',
        body: JSON.stringify({ avatarId }),
      }),
  },

  wallet: {
    getBalance: () => api.request('/wallet/balance'),
    getAddress: () => api.request('/wallet/address'),
    deposit: (txId: string) =>
      api.request('/wallet/deposit', {
        method: 'POST',
        body: JSON.stringify({ txId }),
      }),
    withdraw: (amount: number, address: string) =>
      api.request('/wallet/withdraw', {
        method: 'POST',
        body: JSON.stringify({ amount, address }),
      }),
    getTransactions: () => api.request('/wallet/transactions'),
  },

  rooms: {
    list: (type?: string) => api.request(`/rooms${type ? `?type=${type}` : ''}`),
    create: (type: string, stake: number, maxPlayers: number) =>
      api.request('/rooms/create', {
        method: 'POST',
        body: JSON.stringify({ type, stake, maxPlayers }),
      }),
    join: (roomId: string) =>
      api.request('/rooms/join', {
        method: 'POST',
        body: JSON.stringify({ roomId }),
      }),
  },

  leaderboard: () => api.request('/leaderboard'),
};

// ==================== CONTEXT ====================
interface StoreContextType {
  user: User | null;
  token: string | null;
  transactions: Transaction[];
  rooms: Room[];
  activeGame: Game | null;
  login: (playerId: string, password: string) => Promise<boolean>;
  signup: (password: string) => Promise<boolean>;
  logout: () => void;
  verifyAccount: (txId: string) => Promise<boolean>;
  updateUsername: (username: string) => Promise<boolean>;
  updateAvatar: (avatarId: string) => Promise<void>;
  deposit: (txId: string) => Promise<boolean>;
  withdraw: (amount: number, address: string) => Promise<boolean>;
  createGame: (type: string, stake: number, maxPlayers: number) => Promise<void>;
  joinGame: (roomId: string) => Promise<void>;
  fetchRooms: () => Promise<void>;
  toggleHideBalance: () => Promise<void>;
}

const StoreContext = createContext<StoreContextType | null>(null);

export const useStore = () => {
  const context = useContext(StoreContext);
  if (!context) throw new Error('useStore must be used within StoreProvider');
  return context;
};

export const StoreProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [rooms, setRooms] = useState<Room[]>([]);
  const [activeGame, setActiveGame] = useState<Game | null>(null);

  useEffect(() => {
    if (token) {
      api.auth.verifyToken(token).then((data) => {
        if (data.valid) {
          setUser(data.user);
          fetchUserData();
        } else {
          logout();
        }
      }).catch(() => logout());
    }
  }, [token]);

  const fetchUserData = async () => {
    try {
      const [meData, txData] = await Promise.all([
        api.account.getMe(),
        api.wallet.getTransactions(),
      ]);
      setUser(meData.user);
      setTransactions(txData.transactions || []);
    } catch (error) {
      console.error('Failed to fetch user data:', error);
    }
  };

  const login = async (playerId: string, password: string) => {
    try {
      const data = await api.auth.login(playerId, password);
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('token', data.token);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const signup = async (password: string) => {
    try {
      const data = await api.auth.signup(password);
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('token', data.token);
      return true;
    } catch (error) {
      console.error('Signup failed:', error);
      return false;
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  const verifyAccount = async (txId: string) => {
    try {
      await api.account.verify(txId);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Verification failed:', error);
      return false;
    }
  };

  const updateUsername = async (username: string) => {
    try {
      await api.account.updateUsername(username);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Update username failed:', error);
      return false;
    }
  };

  const updateAvatar = async (avatarId: string) => {
    try {
      await api.account.updateAvatar(avatarId);
      await fetchUserData();
    } catch (error) {
      console.error('Update avatar failed:', error);
    }
  };

  const deposit = async (txId: string) => {
    try {
      await api.wallet.deposit(txId);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Deposit failed:', error);
      return false;
    }
  };

  const withdraw = async (amount: number, address: string) => {
    try {
      await api.wallet.withdraw(amount, address);
      await fetchUserData();
      return true;
    } catch (error) {
      console.error('Withdraw failed:', error);
      return false;
    }
  };

  const createGame = async (type: string, stake: number, maxPlayers: number) => {
    try {
      const data = await api.rooms.create(type, stake, maxPlayers);
      setActiveGame({ gameId: data.roomId, type, stake, players: [], status: 'WAITING' } as any);
    } catch (error) {
      console.error('Create game failed:', error);
    }
  };

  const joinGame = async (roomId: string) => {
    try {
      await api.rooms.join(roomId);
      const room = rooms.find(r => r.id === roomId);
      if (room) {
        setActiveGame({ gameId: room.id, type: room.type, stake: room.stake, players: [], status: 'WAITING' } as any);
      }
    } catch (error) {
      console.error('Join game failed:', error);
    }
  };

  const fetchRooms = async () => {
    try {
      const data = await api.rooms.list();
      setRooms(data.rooms || []);
    } catch (error) {
      console.error('Fetch rooms failed:', error);
    }
  };

  const toggleHideBalance = async () => {
    try {
      await api.request('/account/toggle-balance', { method: 'POST' });
      await fetchUserData();
    } catch (error) {
      console.error('Toggle hide balance failed:', error);
    }
  };

  return (
    <StoreContext.Provider
      value={{
        user,
        token,
        transactions,
        rooms,
        activeGame,
        login,
        signup,
        logout,
        verifyAccount,
        updateUsername,
        updateAvatar,
        deposit,
        withdraw,
        createGame,
        joinGame,
        fetchRooms,
        toggleHideBalance,
      }}
    >
      {children}
    </StoreContext.Provider>
  );
};

// ==================== COMPONENTS ====================

const Landing = () => {
  const navigate = useNavigate();
  const { user } = useStore();

  useEffect(() => {
    if (user) navigate('/');
  }, [user]);

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-b from-gray-900 to-black">
      <div className="text-center max-w-md">
        <h1 className="text-6xl font-black mb-4 bg-gradient-to-r from-yellow-400 to-orange-500 text-transparent bg-clip-text">
          ZEC ARENA
        </h1>
        <p className="text-gray-400 mb-8">Privacy-First PvP Gaming</p>
        <button
          onClick={() => navigate('/auth')}
          className="w-full bg-yellow-500 text-black font-bold py-4 rounded-xl hover:bg-yellow-400 transition"
        >
          PLAY ANONYMOUSLY
        </button>
      </div>
    </div>
  );
};

const Auth = () => {
  const [isLogin, setIsLogin] = useState(false);
  const [playerId, setPlayerId] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, signup } = useStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const success = isLogin ? await login(playerId, password) : await signup(password);
    setLoading(false);
    if (success) navigate('/');
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-gradient-to-b from-gray-900 to-black">
      <div className="w-full max-w-md bg-gray-800 p-8 rounded-2xl">
        <div className="flex gap-4 mb-6">
          <button onClick={() => setIsLogin(false)} className={`flex-1 pb-2 ${!isLogin ? 'border-b-2 border-yellow-500' : ''}`}>
            SIGN UP
          </button>
          <button onClick={() => setIsLogin(true)} className={`flex-1 pb-2 ${isLogin ? 'border-b-2 border-yellow-500' : ''}`}>
            LOGIN
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          {isLogin && (
            <input
              type="text"
              placeholder="Player ID or Username"
              value={playerId}
              onChange={(e) => setPlayerId(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
            />
          )}
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-gray-700 px-4 py-3 rounded-xl text-white"
          />
          <button type="submit" disabled={loading} className="w-full bg-yellow-500 text-black font-bold py-3 rounded-xl">
            {loading ? 'Loading...' : isLogin ? 'LOGIN' : 'CREATE ID'}
          </button>
        </form>
      </div>
    </div>
  );
};

const HomePage = () => {
  const { user } = useStore();
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold">Welcome, {user?.username || `Agent ${user?.playerId.slice(0, 6)}`}</h1>
      <div className="bg-gray-800 p-6 rounded-2xl">
        <h2 className="text-xl font-bold mb-2">PVP MODE</h2>
        <p className="text-gray-400 mb-4">Stake ZEC. Win Big.</p>
        <button className="bg-yellow-500 text-black font-bold px-6 py-2 rounded-xl">
          Play Now
        </button>
      </div>
    </div>
  );
};

const WalletPage = () => {
  const { user, transactions, deposit, withdraw, toggleHideBalance } = useStore();
  const [showDeposit, setShowDeposit] = useState(false);
  const [txId, setTxId] = useState('');

  const handleDeposit = async () => {
    await deposit(txId);
    setShowDeposit(false);
    setTxId('');
  };

  return (
    <div className="p-6 space-y-6">
      <div className="bg-gray-800 p-8 rounded-2xl text-center">
        <p className="text-gray-400 text-sm mb-2">Balance</p>
        <h2 className="text-4xl font-bold mb-2">
          {user?.hideBalance ? '****' : `${user?.balance.toFixed(4)} ZEC`}
        </h2>
        <button onClick={toggleHideBalance} className="text-sm text-gray-500">
          {user?.hideBalance ? 'Show' : 'Hide'}
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <button onClick={() => setShowDeposit(true)} className="bg-green-600 p-4 rounded-xl font-bold">
          Deposit
        </button>
        <button className="bg-red-600 p-4 rounded-xl font-bold">
          Withdraw
        </button>
      </div>

      {showDeposit && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-gray-800 p-6 rounded-2xl w-full max-w-md">
            <h3 className="text-xl font-bold mb-4">Deposit ZEC</h3>
            <input
              type="text"
              placeholder="Transaction ID"
              value={txId}
              onChange={(e) => setTxId(e.target.value)}
              className="w-full bg-gray-700 px-4 py-3 rounded-xl mb-4"
            />
            <div className="flex gap-2">
              <button onClick={() => setShowDeposit(false)} className="flex-1 bg-gray-700 py-3 rounded-xl">
                Cancel
              </button>
              <button onClick={handleDeposit} className="flex-1 bg-yellow-500 text-black py-3 rounded-xl font-bold">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-2">
        <h3 className="font-bold">Transactions</h3>
        {transactions.map((tx) => (
          <div key={tx.id} className="bg-gray-800 p-4 rounded-xl flex justify-between">
            <div>
              <p className="font-bold">{tx.type}</p>
              <p className="text-sm text-gray-500">{new Date(tx.createdAt).toLocaleDateString()}</p>
            </div>
            <p className="font-bold">{tx.amount.toFixed(4)} ZEC</p>
          </div>
        ))}
      </div>
    </div>
  );
};

const ProfilePage = () => {
  const { user, logout } = useStore();
  const navigate = useNavigate();

  return (
    <div className="p-6 space-y-6">
      <div className="text-center">
        <div className="w-24 h-24 bg-yellow-500 rounded-full mx-auto mb-4"></div>
        <h2 className="text-2xl font-bold">{user?.username || `Agent ${user?.playerId}`}</h2>
        <p className="text-gray-400">{user?.playerId}</p>
        {user?.isVerified ? (
          <span className="text-green-400 text-sm">✓ Verified</span>
        ) : (
          <span className="text-red-400 text-sm">✗ Unverified</span>
        )}
      </div>

      <div className="space-y-2">
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>Wins</span>
          <span className="font-bold">{user?.wins}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>Losses</span>
          <span className="font-bold">{user?.losses}</span>
        </div>
        <div className="bg-gray-800 p-4 rounded-xl flex justify-between">
          <span>XP</span>
          <span className="font-bold">{user?.xp}</span>
        </div>
      </div>

      <button onClick={logout} className="w-full bg-red-600 py-3 rounded-xl font-bold">
        Logout
      </button>
    </div>
  );
};

const BottomNav = () => {
  const navigate = useNavigate();
  const location = window.location.pathname;

  const navItems = [
    { path: '/', icon: Home, label: 'Home' },
    { path: '/games', icon: Gamepad2, label: 'Games' },
    { path: '/wallet', icon: Wallet, label: 'Wallet' },
    { path: '/profile', icon: User, label: 'Profile' },
  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 bg-gray-900 border-t border-gray-800 px-6 py-4">
      <div className="flex justify-around">
        {navItems.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={`flex flex-col items-center gap-1 ${
              location === item.path ? 'text-yellow-500' : 'text-gray-500'
            }`}
          >
            <item.icon size={24} />
            <span className="text-xs">{item.label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
};

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user } = useStore();
  return user ? <>{children}</> : <Navigate to="/landing" />;
};

// ==================== MAIN APP ====================
const App = () => {
  return (
    <StoreProvider>
      <Router>
        <div className="min-h-screen bg-black text-white pb-20">
          <Routes>
            <Route path="/landing" element={<Landing />} />
            <Route path="/auth" element={<Auth />} />
            <Route path="/" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
            <Route path="/games" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
            <Route path="/wallet" element={<ProtectedRoute><WalletPage /></ProtectedRoute>} />
            <Route path="/profile" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
          </Routes>
          {window.location.pathname !== '/landing' && window.location.pathname !== '/auth' && <BottomNav />}
        </div>
      </Router>
    </StoreProvider>
  );
};

export default App;
