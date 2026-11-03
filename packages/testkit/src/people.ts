import type { AuthorityItem } from '@umis/core';
import type { PersonKey } from './world.js';

/** The people of the demo. Everyone and everything in it is invented: the names stand for typical roles. */
export const PERSON_NAMES: Readonly<Record<PersonKey, string>> = {
  oleg: 'Олег Бондар',
  ivan: 'Іван Мельник',
  maria: 'Марія Коваль',
};

export const ROLES = {
  resident: { code: 'resident', name: 'Резидент' },
  crewLead: { code: 'crew_lead', name: 'Керівник бригади' },
  crewMember: { code: 'crew_member', name: 'Член бригади' },
  storekeeper: { code: 'storekeeper', name: 'Комірник' },
} as const;

export const BRIDGE_CREW = { id: 'bridge-crew', name: 'Бригада будівництва мосту' } as const;

/** What a crew lead may receive for the bridge site: 10 t of rebar per shift. */
export function crewLeadAuthority(): AuthorityItem[] {
  return [
    {
      action: 'receive_materials',
      resource: 'rebar',
      limit: { amount: 10, unit: 't', per: 'shift' },
      object: 'bridge-01',
    },
  ];
}

/** What the crew lead hands on to a crew member: the same power, 8 t of rebar per shift. */
export function crewMemberAuthority(): AuthorityItem[] {
  return [
    {
      action: 'receive_materials',
      resource: 'rebar',
      limit: { amount: 8, unit: 't', per: 'shift' },
      object: 'bridge-01',
    },
  ];
}
