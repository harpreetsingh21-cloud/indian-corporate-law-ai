import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Crown, Loader2, X, ShieldCheck, Smartphone } from 'lucide-react'
import toast from 'react-hot-toast'
import { authAPI } from '../../../shared/utils/api'
import { useAuthStore } from '../../auth/models/authStore'

export default function UpgradeButton() {
  const { user, login } = useAuthStore()
  const [busy, setBusy] = useState(false)
  const [showPay, setShowPay] = useState(false)
  const [orderId, setOrderId] = useState(null)
  const startedAt = useRef(0)

  const isPro = user?.subscription_tier === 'pro'

  useEffect(() => {
    if (!orderId) return
    startedAt.current = Date.now()
    const t = setInterval(async () => {
      if (Date.now() - startedAt.current > 10 * 60 * 1000) {
        clearInterval(t)
        setOrderId(null)
        return toast.error('Payment timed out. Please try again.')
      }
      try {
        const res = await authAPI.paymentStatus(orderId)
        if (res.state === 'COMPLETED') {
          clearInterval(t)
          setOrderId(null)
          setShowPay(false)
          await login({ ...user, subscription_tier: 'pro', subscription_expiry: res.expires, unlimited: true })
          toast.success(`You're on Pro until ${new Date(res.expires).toLocaleDateString()}!`)
        } else if (res.state === 'FAILED') {
          clearInterval(t)
          setOrderId(null)
          toast.error('Payment failed')
        }
      } catch { }
    }, 3000)
    return () => clearInterval(t)
  }, [orderId])

  const upgrade = async () => {
    const win = window.open('', '_blank')
    if (!win) return toast.error('Please allow pop-ups for this site to open PhonePe.')
    setBusy(true)
    try {
      const order = await authAPI.createOrder()
      win.location.href = order.redirect_url
      setOrderId(order.order_id)
    } catch (err) {
      win.close()
      toast.error(err.message || 'Could not start payment')
    } finally {
      setBusy(false)
    }
  }

  if (user?.role === 'admin') return null

  return (
    <div className="flex flex-col gap-1.5">
      {isPro && (
        <div className="text-[11px] font-semibold text-green-600 dark:text-green-400 text-center font-poppins">
          Pro active{user?.subscription_expiry ? ` until ${new Date(user.subscription_expiry).toLocaleDateString()}` : ''}
        </div>
      )}
      <button
        onClick={() => setShowPay(true)}
        disabled={busy}
        className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-orange-500 to-amber-500 text-white font-outfit font-bold text-sm shadow-md shadow-orange-500/30 hover:opacity-90 disabled:opacity-50"
      >
        {busy ? <Loader2 size={16} className="animate-spin" /> : <Crown size={16} />}
        {isPro ? 'Renew Pro · ₹299/month' : 'Upgrade to Pro · ₹299/month'}
      </button>

      <div className="text-[10px] text-center text-gray-400 dark:text-gray-500 font-poppins">
        Secure payments by PhonePe
      </div>

      {showPay && createPortal(
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={() => !busy && !orderId && setShowPay(false)}>
          <div className="w-full max-w-md rounded-3xl overflow-hidden bg-white dark:bg-neutral-950 border border-gray-200 dark:border-neutral-800 shadow-2xl font-poppins" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 bg-gradient-to-r from-orange-500 to-amber-500 text-white">
              <div className="flex items-center gap-2.5">
                <Crown size={20} />
                <div>
                  <div className="font-outfit font-extrabold text-lg leading-tight">LegalBuddy Pro</div>
                  <div className="text-xs opacity-90">Unlimited uploads for 30 days</div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="font-outfit font-black text-2xl">₹299</div>
                <button onClick={() => { setOrderId(null); setShowPay(false) }} disabled={busy} className="p-1 rounded-lg hover:bg-white/20 disabled:opacity-50">
                  <X size={18} />
                </button>
              </div>
            </div>

            <div className="p-6 flex flex-col gap-4">
              <div className="text-sm font-bold text-gray-900 dark:text-white font-outfit">Pay securely with PhonePe</div>
              <div className="flex flex-wrap gap-1.5">
                {['UPI', 'Cards', 'NetBanking'].map((m) => (
                  <span key={m} className="px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20">
                    {m}
                  </span>
                ))}
              </div>
              <button
                onClick={upgrade}
                disabled={busy || !!orderId}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-[#5f259f] hover:bg-[#4e1f84] text-white font-outfit font-bold text-sm shadow-md disabled:opacity-60"
              >
                {busy || orderId ? <Loader2 size={16} className="animate-spin" /> : <Smartphone size={16} />}
                {orderId ? 'Waiting for PhonePe payment…' : 'Pay ₹299 with PhonePe'}
              </button>
              {orderId && (
                <p className="text-[11px] text-center text-gray-500 dark:text-gray-400 leading-relaxed">
                  Complete the payment in the PhonePe tab. This window updates by itself.
                </p>
              )}
              <div className="flex items-center justify-center gap-1.5 text-[11px] text-gray-400 dark:text-gray-500">
                <ShieldCheck size={13} className="text-green-500" /> 100% secure · Secured by PhonePe
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}