import React from "react";
import { getSeededDemoReports } from "@/lib/demo-fixtures";
import { SupplyGuardApp } from "@/components/SupplyGuardApp";

export default async function HomePage() {
  const initialReports = await getSeededDemoReports();
  return <SupplyGuardApp initialReports={initialReports} />;
}
