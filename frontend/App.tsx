import { HashRouter, Route, Routes } from 'react-router-dom';
import { Layout } from './components/Layout';
import { StoreProvider } from './services/store';
import Alerts from './pages/Alerts';
import Dashboard from './pages/Dashboard';
import FileIntegrity from './pages/FileIntegrity';
import HostMonitor from './pages/HostMonitor';
import IncidentTimeline from './pages/IncidentTimeline';
import NetworkMonitor from './pages/NetworkMonitor';
import ProcessMonitor from './pages/ProcessMonitor';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import ThreatDetection from './pages/ThreatDetection';

export default function App() {
  return (
    <StoreProvider>
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="network" element={<NetworkMonitor />} />
            <Route path="host" element={<HostMonitor />} />
            <Route path="process" element={<ProcessMonitor />} />
            <Route path="files" element={<FileIntegrity />} />
            <Route path="threats" element={<ThreatDetection />} />
            <Route path="incidents" element={<IncidentTimeline />} />
            <Route path="incidents/:id" element={<IncidentTimeline />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </HashRouter>
    </StoreProvider>
  );
}
