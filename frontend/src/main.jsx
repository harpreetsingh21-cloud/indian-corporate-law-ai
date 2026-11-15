import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './core/App'
import PaymentDoneView from './features/profile/views/PaymentDoneView'
import { useAuthStore } from './features/auth/models/authStore'
useAuthStore.getState().initAuth()
const isPaymentDone = window.location.pathname.startsWith('/payment-done')
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      {isPaymentDone ? <PaymentDoneView /> : <App />}
    </BrowserRouter>
  </StrictMode>
)