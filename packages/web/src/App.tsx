import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import DashboardLayout from './components/DashboardLayout';
import HomePage from './pages/HomePage';
import FeaturesPage from './pages/FeaturesPage';
import PricingPage from './pages/PricingPage';
import DocsPage from './pages/DocsPage';
import GuidePage from './pages/GuidePage';
import AboutPage from './pages/AboutPage';
import DashboardOverview from './pages/dashboard/DashboardOverview';
import DashboardScan from './pages/dashboard/DashboardScan';
import DashboardReport from './pages/dashboard/DashboardReport';
import DashboardThreat from './pages/dashboard/DashboardThreat';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import WaitlistVerify from './pages/WaitlistVerify';

export default function App() {
  return (
    <Routes>
      {/* Marketing site */}
      <Route element={<Layout />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/features" element={<FeaturesPage />} />
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/guide" element={<GuidePage />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/waitlist/verify/:token" element={<WaitlistVerify />} />
      </Route>

      {/* Dashboard */}
      <Route path="/dashboard" element={<DashboardLayout />}>
        <Route index element={<DashboardOverview />} />
        <Route path="scan" element={<DashboardScan />} />
        <Route path="report" element={<DashboardReport />} />
        <Route path="threat" element={<DashboardThreat />} />
      </Route>
    </Routes>
  );
}
