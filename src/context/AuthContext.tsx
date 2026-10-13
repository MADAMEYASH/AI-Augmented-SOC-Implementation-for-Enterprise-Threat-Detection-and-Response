import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  onAuthStateChanged,
  signInWithPopup,
  signOut as fbSignOut,
} from 'firebase/auth';
import { auth, googleAuthProvider } from '../lib/firebase.ts';
import { setAuthTokenGetter, fetchCurrentUserProfile } from '../services/api.ts';

export type UserRole = 'admin' | 'analyst' | 'auditor';

export interface DbUserProfile {
  uid: string;
  email: string;
  name?: string;
  role: UserRole;
  createdAt?: string;
}

interface AuthContextType {
  user: User | null;
  dbUser: DbUserProfile | null;
  idToken: string | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signOut: () => Promise<void>;
  isSimulatedMode: boolean;
  setIsSimulatedMode: (val: boolean) => void;
  canExecuteActions: boolean;
  canApproveActions: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [dbUser, setDbUser] = useState<DbUserProfile | null>(null);
  const [idToken, setIdToken] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isSimulatedMode, setIsSimulatedMode] = useState<boolean>(false);

  // Register token getter for API client
  useEffect(() => {
    setAuthTokenGetter(async () => {
      if (!auth.currentUser) return null;
      try {
        return await auth.currentUser.getIdToken();
      } catch (e) {
        return null;
      }
    });
  }, []);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        try {
          const token = await currentUser.getIdToken();
          setIdToken(token);
          const profile = await fetchCurrentUserProfile();
          setDbUser(profile);
        } catch (e) {
          console.warn('Failed to fetch user DB profile:', e);
          setDbUser({
            uid: currentUser.uid,
            email: currentUser.email || 'analyst@corp.internal',
            name: currentUser.displayName || 'SOC Analyst',
            role: 'analyst',
          });
        }
      } else {
        setIdToken(null);
        // Default local SOC profile when not signed in
        setDbUser({
          uid: 'local-soc-lead',
          email: 'lead.analyst@corp.internal',
          name: 'Lead Incident Commander',
          role: 'admin',
        });
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    try {
      await signInWithPopup(auth, googleAuthProvider);
    } catch (error) {
      console.error('Sign in failed:', error);
      throw error;
    }
  };

  const signOut = async () => {
    try {
      await fbSignOut(auth);
      setUser(null);
      setIdToken(null);
    } catch (error) {
      console.error('Sign out failed:', error);
    }
  };

  const canExecuteActions = dbUser?.role === 'admin' || dbUser?.role === 'analyst';
  const canApproveActions = dbUser?.role === 'admin';

  return (
    <AuthContext.Provider
      value={{
        user,
        dbUser,
        idToken,
        loading,
        signInWithGoogle,
        signOut,
        isSimulatedMode,
        setIsSimulatedMode,
        canExecuteActions,
        canApproveActions,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
