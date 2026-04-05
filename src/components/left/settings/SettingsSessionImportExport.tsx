import type React from '../../../lib/teact/teact';
import { memo, useRef, useState } from '../../../lib/teact/teact';

import type { SharedSessionData } from '../../../types';

import { SESSION_ACCOUNT_PREFIX } from '../../../config';
import { IS_MULTIACCOUNT_SUPPORTED } from '../../../util/browser/globalEnvironment';
import buildClassName from '../../../util/buildClassName';
import {
  getAccountsInfo,
  loadSlotSession,
  writeSlotSession,
} from '../../../util/multiaccount';

import useFlag from '../../../hooks/useFlag';
import useHistoryBack from '../../../hooks/useHistoryBack';
import useLang from '../../../hooks/useLang';
import useLastCallback from '../../../hooks/useLastCallback';

import Button from '../../ui/Button';
import Checkbox from '../../ui/Checkbox';
import ConfirmDialog from '../../ui/ConfirmDialog';

import styles from './SettingsSessionImportExport.module.scss';

type OwnProps = {
  isActive?: boolean;
  onReset: () => void;
};

type ExportedSessionData = {
  version: number;
  exportedAt: number;
  sessions: Array<{
    slot: number;
    data: SharedSessionData;
  }>;
};

const EXPORT_VERSION = 1;

function findFreeSlot(existingSlots: number[]): number {
  let slot = 1;
  while (existingSlots.includes(slot)) {
    slot++;
  }
  return slot;
}

const SettingsSessionImportExport = ({ isActive, onReset }: OwnProps) => {
  const lang = useLang();
  const fileInputRef = useRef<HTMLInputElement>();

  const accountsInfo = getAccountsInfo();
  const allSlots = Object.keys(accountsInfo).map(Number);

  const [selectedSlots, setSelectedSlots] = useState<Set<number>>(new Set(allSlots));
  const [isImportConfirmOpen, openImportConfirm, closeImportConfirm] = useFlag();
  const [pendingImportData, setPendingImportData] = useState<ExportedSessionData | undefined>();
  const [importResult, setImportResult] = useState<'success' | 'error' | undefined>();

  useHistoryBack({ isActive, onBack: onReset });

  const handleToggleSlot = useLastCallback((slot: number) => {
    setSelectedSlots((prev) => {
      const next = new Set(prev);
      if (next.has(slot)) {
        next.delete(slot);
      } else {
        next.add(slot);
      }
      return next;
    });
  });

  const handleSelectAll = useLastCallback(() => {
    if (selectedSlots.size === allSlots.length) {
      setSelectedSlots(new Set());
    } else {
      setSelectedSlots(new Set(allSlots));
    }
  });

  const handleExport = useLastCallback(() => {
    const sessions: ExportedSessionData['sessions'] = [];

    for (const slot of selectedSlots) {
      const data = loadSlotSession(slot);
      if (data) {
        sessions.push({ slot, data });
      }
    }

    if (!sessions.length) return;

    const exportData: ExportedSessionData = {
      version: EXPORT_VERSION,
      exportedAt: Date.now(),
      sessions,
    };

    const json = JSON.stringify(exportData, undefined, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tg-sessions-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  const handleImportFileChange = useLastCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const parsed = JSON.parse(ev.target?.result as string) as ExportedSessionData;
        if (!parsed.version || !Array.isArray(parsed.sessions)) {
          setImportResult('error');
          return;
        }
        setPendingImportData(parsed);
        openImportConfirm();
      } catch {
        setImportResult('error');
      }
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    };
    reader.readAsText(file);
  });

  const handleConfirmImport = useLastCallback(() => {
    if (!pendingImportData) return;
    closeImportConfirm();

    const existingSlots = Object.keys(localStorage)
      .filter((k) => k.startsWith(SESSION_ACCOUNT_PREFIX))
      .map((k) => Number(k.slice(SESSION_ACCOUNT_PREFIX.length)));

    for (const { data } of pendingImportData.sessions) {
      const existingMatchSlot = existingSlots.find((s) => {
        const existing = loadSlotSession(s);
        return existing?.userId && existing.userId === data.userId;
      });

      const targetSlot = existingMatchSlot ?? findFreeSlot(existingSlots);
      writeSlotSession(targetSlot, data);
      if (!existingSlots.includes(targetSlot)) {
        existingSlots.push(targetSlot);
      }
    }

    setPendingImportData(undefined);
    setImportResult('success');

    setTimeout(() => {
      window.location.reload();
    }, 1500);
  });

  const handleCancelImport = useLastCallback(() => {
    closeImportConfirm();
    setPendingImportData(undefined);
  });

  const handleImportClick = useLastCallback(() => {
    fileInputRef.current?.click();
  });

  const isAllSelected = selectedSlots.size === allSlots.length;
  const hasAccounts = allSlots.length > 0;

  return (
    <div className="settings-content custom-scroll">
      {/* Export */}
      <div className="settings-item">
        <h4 className="settings-item-header">{lang('SettingsSessionExport')}</h4>
        <p className="settings-item-description">{lang('SettingsSessionExportDescription')}</p>

        {hasAccounts ? (
          <>
            <div className={styles.accountList}>
              <div className={styles.selectAllRow}>
                <Checkbox
                  label={lang('SettingsSessionExportSelectAll')}
                  checked={isAllSelected}
                  onChange={handleSelectAll}
                />
              </div>
              {allSlots.map((slot) => {
                const info = accountsInfo[slot];
                const displayName = [info.firstName, info.lastName].filter(Boolean).join(' ')
                  || info.phone
                  || `Account ${slot}`;
                return (
                  <div key={slot} className={styles.accountRow}>
                    <Checkbox
                      label={displayName}
                      checked={selectedSlots.has(slot)}
                      onChange={() => handleToggleSlot(slot)}
                    />
                    {info.phone && Boolean([info.firstName, info.lastName].filter(Boolean).join(' ')) && (
                      <span className={styles.accountPhone}>{info.phone}</span>
                    )}
                  </div>
                );
              })}
            </div>
            <Button
              className="settings-button"
              color="primary"
              iconName="download"
              isText
              noForcedUpperCase
              disabled={!selectedSlots.size}
              onClick={handleExport}
            >
              {lang('SettingsSessionExportAll')}
            </Button>
          </>
        ) : (
          <p className="settings-item-description">{lang('FilterNoChatsToDisplay')}</p>
        )}
      </div>

      {/* Import */}
      <div className="settings-item">
        <h4 className="settings-item-header">{lang('SettingsSessionImport')}</h4>
        <p className="settings-item-description">{lang('SettingsSessionImportDescription')}</p>
        {IS_MULTIACCOUNT_SUPPORTED && (
          <Button
            className="settings-button"
            color="primary"
            iconName="document"
            isText
            noForcedUpperCase
            onClick={handleImportClick}
          >
            {lang('SettingsSessionImport')}
          </Button>
        )}
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          className={styles.hiddenInput}
          onChange={handleImportFileChange}
        />
      </div>

      {importResult === 'success' && (
        <div className={buildClassName('settings-item', styles.resultMsg, styles.successMsg)}>
          <p>{lang('SettingsSessionImportSuccess')}</p>
        </div>
      )}
      {importResult === 'error' && (
        <div className={buildClassName('settings-item', styles.resultMsg, styles.errorMsg)}>
          <p>{lang('SettingsSessionImportError')}</p>
        </div>
      )}

      <ConfirmDialog
        isOpen={isImportConfirmOpen}
        title={lang('SettingsSessionImportConfirmTitle')}
        text={lang('SettingsSessionImportConfirmText', { count: String(pendingImportData?.sessions.length ?? 0) })}
        confirmLabel={lang('OK')}
        confirmHandler={handleConfirmImport}
        onClose={handleCancelImport}
      />
    </div>
  );
};

export default memo(SettingsSessionImportExport);
