import { Download, Eye, Trash2, FileText, File, FileType, Clock, HardDrive, CheckCircle } from 'lucide-react'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import toast from 'react-hot-toast'
import { removeFile, downloadFile } from '../../../shared/utils/storage'
import PDFViewer from './PDFViewerView'

const getExt = (file) => {
  const fromName = file.name?.split('.').pop()?.toUpperCase()
  if (['PDF', 'DOCX', 'TXT'].includes(fromName)) return fromName
  if (file.type === 'application/pdf') return 'PDF'
  if (file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'DOCX'
  return 'TXT'
}

const TYPE_BADGE = {
  PDF: 'bg-orange-100 text-orange-800 dark:bg-orange-500/10 dark:text-orange-500',
  DOCX: 'bg-blue-100 text-blue-800 dark:bg-blue-500/10 dark:text-blue-500',
  TXT: 'bg-gray-100 text-gray-800 dark:bg-gray-500/10 dark:text-gray-500',
}

const BADGE_BASE = 'text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md'

function TypeIcon({ ext }) {
  if (ext === 'PDF') return <FileText size={20} className="text-orange-500" />
  if (ext === 'DOCX') return <File size={20} className="text-blue-500" />
  return <FileType size={20} className="text-gray-500 dark:text-gray-400" />
}

export default function DocumentFiles({ files, isDark, onFileDeleted }) {
  const [selectedFile, setSelectedFile] = useState(null)

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  const formatSize = (size) => {
    if (typeof size === 'string') {
      return size + ' MB'
    }
    return size > 1024 ? (size / 1024).toFixed(1) + ' MB' : size + ' KB'
  }

  const handleView = (file) => {
    setSelectedFile(file)
    toast.success('Opening file...')
  }

  const handleDownload = (file) => {
    try {
      downloadFile(file)
      toast.success('File downloaded successfully!')
    } catch (error) {
      toast.error('Error downloading file')
      console.error('Download error:', error)
    }
  }

  const handleDelete = (file) => {
    if (file.isDummy) {
      toast.error('Cannot delete sample files')
      return
    }

    if (confirm(`Delete "${file.name}"?`)) {
      try {
        removeFile(file.id)
        toast.success('File deleted successfully')
        if (onFileDeleted) {
          onFileDeleted()
        }
      } catch (error) {
        toast.error('Error deleting file')
        console.error('Delete error:', error)
      }
    }
  }

  if (files.length === 0) {
    return (
      <div className="text-center py-12 rounded-2xl bg-white dark:bg-[#111111] border border-gray-200 dark:border-[#1f1f1f]">
        <FileText className="w-12 h-12 mx-auto mb-4 text-gray-400 dark:text-gray-600" />
        <p className="text-lg font-semibold text-gray-900 dark:text-white">
          No documents uploaded yet
        </p>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Upload your first legal document to get started
        </p>
      </div>
    )
  }

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <AnimatePresence>
          {files.map((file, i) => {
            const ext = getExt(file)
            const analyzed = file.status === 'COMPLETED' || file.analyzed

            return (
              <motion.div
                key={file.id}
                layout
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ delay: i * 0.03 }}
                className="bg-white dark:bg-[#161616] rounded-2xl p-6 border border-gray-200 dark:border-[#1f1f1f] hover:border-orange-500/40 transition-colors cursor-pointer group relative"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
                    <TypeIcon ext={ext} />
                  </div>

                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => handleView(file)}
                      className="p-1.5 rounded-lg bg-orange-500/10 text-orange-500 hover:bg-orange-500/20"
                      title="View"
                    >
                      <Eye size={14} />
                    </button>
                    <button
                      onClick={() => handleDownload(file)}
                      className="p-1.5 rounded-lg bg-orange-500/10 text-orange-500 hover:bg-orange-500/20"
                      title="Download"
                    >
                      <Download size={14} />
                    </button>
                    {!file.isDummy && (
                      <button
                        onClick={() => handleDelete(file)}
                        className="p-1.5 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500/20"
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </div>

                <h3 className="text-gray-900 dark:text-white font-bold text-base truncate">
                  {file.name?.replace(/\.[^.]+$/, '')}
                </h3>

                <div className="flex items-center gap-2 mt-3">
                  <span className={`${BADGE_BASE} ${TYPE_BADGE[ext] || TYPE_BADGE.TXT}`}>{ext}</span>
                  {file.status !== undefined && (
                    analyzed ? (
                      <span className={`${BADGE_BASE} flex items-center gap-1 bg-green-500/10 text-green-600 dark:text-green-500`}>
                        <CheckCircle size={11} /> Analyzed
                      </span>
                    ) : (
                      <span className={`${BADGE_BASE} flex items-center gap-1 bg-yellow-500/10 text-yellow-600 dark:text-yellow-500`}>
                        <Clock size={11} /> Queued
                      </span>
                    )
                  )}
                  {file.isDummy && (
                    <span className={`${BADGE_BASE} bg-gray-100 text-gray-800 dark:bg-gray-500/10 dark:text-gray-500`}>Sample</span>
                  )}
                </div>

                <div className="space-y-2 text-xs mt-4 text-gray-500 dark:text-gray-400">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    <span>{formatDate(file.uploadedAt)}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <HardDrive className="w-4 h-4" />
                    <span>{formatSize(file.size)}</span>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </AnimatePresence>
      </div>

      {selectedFile && (
        <PDFViewer
          file={selectedFile}
          isDark={isDark}
          onClose={() => setSelectedFile(null)}
        />
      )}
    </>
  )
}